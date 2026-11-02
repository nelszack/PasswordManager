# Local zbus 6 port

Based on crates.io `zbus-lockstep` 0.7.0, retaining its upstream license files.

XML signature validation uses maintained zbus_xml 6 iterators and direct signatures, plus zbus 6 wire signatures. The XML validation checks are retained.

This patch removes the abandoned standalone `zvariant`/`zbus_names` implementation dependencies; it does not suppress advisories. These path sources are maintained locally and are not covered by registry advisory matching. Review upstream changes when upgrading. The DBus codec/transport and XML parser remain registry dependencies covered by `cargo audit --deny warnings`.

The upstream unit-test XML fixture was omitted from the published crate. The
copy in `xml/test_definition_file.xml` comes from the release source commit
`ac20711dd0ce42eb185f19c42d360c12b51aff1e` in
https://github.com/luukvanderduim/zbus-lockstep.
