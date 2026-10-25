# Local Iced software-renderer patch

This is the crates.io `iced_tiny_skia` 0.14.1 source from Iced commit
`0ecf60664df7b8ac7d7aef5f7279d5323027f693` (`tiny_skia/`), with its MIT license.
The root manifest selects it through `[patch.crates-io]`.

The only production change is in `Renderer::draw` (`src/lib.rs`): damage
rectangles round outward to physical pixels before clearing and repainting.
Upstream clears fractional rectangles without antialiasing, which can leave
partially covered pixels from old controls along scrollable clip edges. These
appear as blue lines across different GUI screens, and disappear on a full redraw.
Rounding happens after display scaling, so it also covers fractional DPI scales.

`src/tests.rs` compares incremental scrolling with full redraws at multiple clip
positions and display scales, including controls crossing clip boundaries. It
fails against the unmodified renderer. Run it from the project root:

```sh
cargo test --locked -p iced_tiny_skia --lib
```

Keep the patch limited to this redraw fix. When upgrading Iced, check whether
the upstream renderer passes this regression before removing the local copy.
