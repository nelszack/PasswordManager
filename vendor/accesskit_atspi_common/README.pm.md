# Local zbus 6 port

Based on crates.io `accesskit_atspi_common` 0.18.1, retaining its upstream license files.

Action signatures and rectangle conversions use zbus 6 wire types/derives. Accessibility translation and geometry logic are unchanged.

This patch removes the abandoned standalone `zvariant`/`zbus_names` implementation dependencies; it does not suppress advisories. These path sources are maintained locally and are not covered by registry advisory matching. Review upstream changes when upgrading. The DBus codec/transport and XML parser remain registry dependencies covered by `cargo audit --deny warnings`.
