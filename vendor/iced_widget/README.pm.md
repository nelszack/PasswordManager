# Local Iced widget accessibility patch

Based on crates.io `iced_widget` 0.14.2, retaining its MIT license. Accessibility
operations are adapted from Daniel Hedlund's Iced fork, commit
`68c3226f8c13a247a5225aa788e35ccddbeeb5fe`:
https://github.com/dhedlund/iced/tree/68c3226f8c13a247a5225aa788e35ccddbeeb5fe

Widgets expose roles, names, values, states, and bounds through the patched core
operation visitor. Secure text inputs expose a protected password role and omit
their values. This application also corrects the vertical slider orientation.
No rendering or pointer event implementation is replaced.

Local additions provide independent text-input names, stable input identities,
ordinary-input caret/selection metadata, selected button states, and semantic
menu options forwarded through the overlay. Protected inputs omit both text
contents and selection offsets.
