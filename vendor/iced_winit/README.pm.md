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

Keep this patch limited to backend selection. When upgrading Iced/Winit,
check whether upstream's selected titlebar backend still requires ttf-parser
before removing the local copy. Test decorated Wayland title text and normal
window controls when changing the backend.
