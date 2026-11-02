# Local zbus 6 port

Based on crates.io `zbus-lockstep-macros` 0.7.0, retaining its upstream license files.

Generated XML contract checks use zbus 6 wire types and maintained zbus_xml 6; validation remains enabled.

This patch removes the abandoned standalone `zvariant`/`zbus_names` implementation dependencies; it does not suppress advisories. These path sources are maintained locally and are not covered by registry advisory matching. Review upstream changes when upgrading. The DBus codec/transport and XML parser remain registry dependencies covered by `cargo audit --deny warnings`.
