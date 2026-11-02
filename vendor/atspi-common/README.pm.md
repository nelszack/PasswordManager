# Local zbus 6 port

Based on crates.io `atspi-common` 0.13.0, retaining its upstream license files.

Protocol roles, fields, signatures, and custom serialization are unchanged. Wire/name imports and derives use zbus 6; its unified error type has one conversion. Message builders and unchecked-body decoding use their new APIs.

This patch removes the abandoned standalone `zvariant`/`zbus_names` implementation dependencies; it does not suppress advisories. These path sources are maintained locally and are not covered by registry advisory matching. Review upstream changes when upgrading. The DBus codec/transport and XML parser remain registry dependencies covered by `cargo audit --deny warnings`.

The GetTextSelections XML check validates the return signature: the protocol declares selections as an out parameter. Unit tests retain the upstream event, state, object-reference, serialization, and XML checks.
