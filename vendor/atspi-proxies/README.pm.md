# Local zbus 6 port

Based on crates.io `atspi-proxies` 0.13.0, retaining its upstream license files.

Generated proxies use zbus 6 and infallible destination/path builders. Interface names and method/property signatures are unchanged.

This patch removes the abandoned standalone `zvariant`/`zbus_names` implementation dependencies; it does not suppress advisories. These path sources are maintained locally and are not covered by registry advisory matching. Review upstream changes when upgrading. The DBus codec/transport and XML parser remain registry dependencies covered by `cargo audit --deny warnings`.
