use super::*;
use crate::core::Renderer as _;
use crate::graphics::damage;

fn scene(renderer: &mut Renderer, viewport: &Viewport, origin: f32, offset: f32) {
    renderer.reset(Rectangle::with_size(viewport.logical_size()));
    renderer.fill_quad(
        renderer::Quad {
            bounds: Rectangle::with_size(viewport.logical_size()),
            ..renderer::Quad::default()
        },
        Color::from_rgb8(48, 50, 73),
    );
    renderer.start_layer(Rectangle {
        x: origin,
        y: origin,
        width: 60.0,
        height: 70.0,
    });
    renderer.fill_quad(
        renderer::Quad {
            bounds: Rectangle {
                x: origin,
                y: origin + 5.0 - offset,
                width: 30.0,
                height: 16.0,
            },
            border: core::border::rounded(2),
            ..renderer::Quad::default()
        },
        Color::from_rgb8(42, 195, 222),
    );
    renderer.end_layer();
}

#[test]
fn scrolling_fractional_clip_edges_matches_a_full_redraw() {
    for scale in [1.0, 1.25, 1.5, 2.0] {
        for origin in [10.0, 10.2, 10.4, 10.6, 10.8] {
            let viewport = Viewport::with_physical_size(Size::new(128, 128), scale);
            let full = Rectangle::with_size(viewport.logical_size());
            let mut renderer = Renderer::new(Font::default(), Pixels(16.0));
            let mut pixels = tiny_skia::Pixmap::new(128, 128).unwrap();
            let mut mask = tiny_skia::Mask::new(128, 128).unwrap();
            scene(&mut renderer, &viewport, origin, 0.0);
            renderer.draw(
                &mut pixels.as_mut(),
                &mut mask,
                &viewport,
                &[full],
                Color::BLACK,
            );

            for offset in [-25.0, 4.8, 12.0, 22.0, 0.0] {
                let previous = renderer.layers().to_vec();
                scene(&mut renderer, &viewport, origin, offset);
                let damage = damage::group(
                    damage::diff(
                        &previous,
                        renderer.layers(),
                        |layer| vec![layer.bounds],
                        Layer::damage,
                    ),
                    full,
                );
                renderer.draw(
                    &mut pixels.as_mut(),
                    &mut mask,
                    &viewport,
                    &damage,
                    Color::BLACK,
                );

                let mut expected = tiny_skia::Pixmap::new(128, 128).unwrap();
                renderer.draw(
                    &mut expected.as_mut(),
                    &mut mask,
                    &viewport,
                    &[full],
                    Color::BLACK,
                );
                let mismatch = pixels
                    .pixels()
                    .iter()
                    .zip(expected.pixels())
                    .position(|(a, b)| a != b);
                assert!(
                    mismatch.is_none(),
                    "incremental redraw left stale pixels: scale={scale}, origin={origin}, offset={offset}, pixel={:?}",
                    mismatch.map(|i| (i % 128, i / 128))
                );
            }
        }
    }
}
