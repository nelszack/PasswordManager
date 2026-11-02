# Local Iced accessibility metadata patch

Based on crates.io `iced_core` 0.14.0, retaining its MIT license. Accessibility
metadata and operation forwarding are adapted from Daniel Hedlund's Iced fork,
commit `68c3226f8c13a247a5225aa788e35ccddbeeb5fe`:
https://github.com/dhedlund/iced/tree/68c3226f8c13a247a5225aa788e35ccddbeeb5fe

The patch adds `Operation::accessible` and semantic role/state/value types. The
application additionally distinguishes protected password inputs. No AccessKit
dependency is introduced into this crate. See `vendor/iced_winit/README.pm.md`
for the platform bridge and validation requirements.
