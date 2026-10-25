# Font database compatibility bridge

Cosmic Text 0.15, used by Iced 0.14, requires fontdb 0.23. This local
0.23.1 package forwards its public API and feature flags to upstream fontdb
0.24, whose public declarations are compatible with the consumers in this
application. The root manifest selects the bridge through `[patch.crates-io]`.

Fontdb 0.24 owns a reduced font metadata parser and no longer depends on the
unmaintained ttf-parser crate. This bridge contains no parser code and does not
suppress RustSec advisories. See the [upstream changelog](https://github.com/RazrFalcon/fontdb/blob/master/CHANGELOG.md).

When upgrading Iced/Cosmic Text to a release using fontdb 0.24 or newer, remove
this bridge and its patch entry. Keep all feature flags forwarded so font
discovery, memory mapping, and platform font configuration retain their behavior.
