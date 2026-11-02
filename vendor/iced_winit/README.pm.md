# Local Iced window integration patch

This is crates.io `iced_winit` 0.14.1 from Iced commit
`38237dd294da3256c2ac4d3f8288fc73956c91e0` (`winit/`), with its MIT license.
The root manifest selects it through `[patch.crates-io]`.

The backend change is in the manifest's `wayland` feature: forward to Winit's
`wayland-csd-adwaita-crossfont` backend instead of `wayland-csd-adwaita`.
Crossfont keeps decorated Wayland windows and title text while using the
maintained FreeType/Fontconfig backend instead of the ab_glyph/owned_ttf_parser
path to the unmaintained ttf-parser crate. X11, Windows, macOS, and Iced's
application/window APIs are unchanged.

Two event-queue reads also use futures-channel's current `try_recv` API instead
of deprecated `try_next`, preserving the previous empty/closed queue behavior.

Linux desktop builds need pkg-config, Fontconfig, and FreeType development
packages. CLI-only builds do not include this integration.

## Accessibility integration

The optional `a11y` feature adds the AccessKit platform adapter, semantic tree
builder, and action routing adapted from Daniel Hedlund's Iced fork, commit
`68c3226f8c13a247a5225aa788e35ccddbeeb5fe` (MIT):
https://github.com/dhedlund/iced/tree/68c3226f8c13a247a5225aa788e35ccddbeeb5fe

The application's desktop feature enables this bridge with the local core and
widget metadata patches. CLI-only builds exclude it. This port uses the current
AccessKit 0.24 tree/action API and protected password roles. It omits the fork's
new runtime announcement action; that action is not part of upstream Iced 0.14.
Assistive actions pass through existing widget event handling. Screen-reader,
keyboard, focus, scrolling, menu, and secret-masking checks remain necessary on
each platform; exposing a tree alone does not establish full accessibility.

Ordinary editable values include text runs with grapheme byte lengths so AT-SPI
can read them. Single-line fields expose caret/selection and route selection
requests to their owning widget; requests naming another input's text run are
ignored. Multiline editors use the same path, converting editor line/byte
positions to text-run grapheme offsets and back; native multiline caret and
selection are included in the acceptance script.
Text runs follow stored newline boundaries and preserve global selection offsets
across lines. Soft-wrapped line geometry is not exported separately.
The root transform applies the viewport's display/interface scale for platform
coordinates; synthetic input targets retain their original logical coordinates.

When upgrading Iced/Winit,
check whether upstream's selected titlebar backend still requires ttf-parser
before removing the local copy. Test decorated Wayland title text and normal
window controls when changing the backend.
