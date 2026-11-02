# AT-SPI status compatibility

This is crates.io `accesskit_unix` 0.21.1, retaining its MIT/Apache licenses.
`src/context.rs` watches `org.a11y.Status.IsEnabled` instead of
`ScreenReaderEnabled`. The installed AT-SPI 2.62.1 exposes only `IsEnabled`;
waiting for the removed property silently leaves the adapter inactive.

`IsEnabled` also exists on older AT-SPI installations. Using it may initialize
the accessibility adapter for consumers other than screen readers, which is
appropriate for the native accessibility bus. No desktop preferences are changed.

The root accessible also retains the desktop address returned by the registry's
`Embed` handshake and exposes it as `Parent`. Returning a null parent caused
Orca 51 to reject the application's focus events as unknown to the desktop.

The adapter and its local AT-SPI protocol helpers use maintained `zbus` 6 rather
than the abandoned standalone `zvariant` and `zbus_names` crates. Connection IO
is driven by zbus's runtime; the old manual executor tick tasks are removed.
Object-server insertion follows the new optional previous-interface return.
Protocol signatures and serialization are checked by the crate's wire tests,
and the application acceptance script exercises the real DBus/Orca interaction.
