# CLI and desktop feature map

The desktop uses the same typed server commands as the CLI. This map covers
public commands and their options; terminal presentation and hidden developer or
process entry points have no separate desktop action.

| CLI command | Desktop route |
| --- | --- |
| `gui` | Default launch; Tools → Browser integration installs the Linux shortcut. |
| `genpass`, `passcheck` | Generator: password/passphrase, character groups, exact symbols, ambiguous-character exclusion, length/words/separator, strength check, stats/copy/timeout overrides. |
| `config` | Settings: all persistent CLI defaults, reset, service port, default vault. |
| `unlock`, `new`, `rekey`, `delete --vault` | Vault picker/unlock form and Tools → Vault security: selected filename, password/key file, timeout, creation, credential changes, and external-key retention. |
| `vaults` | Vault picker and refresh, including while the service is stopped. |
| `start`, `status`, `lock`, `kill` | Connection status and refresh, Lock, Settings → Connection → Start/Stop local service. |
| `operation` | Tools → CLI utilities → Check operation outcome, including while locked. The existing pending-operation banner separately reviews this window's uncertain changes. |
| `add`, `update`, `delete` | Vault item editor: all eight types, username, primary secret/manual or generated, notes, multiple URLs, searchable/secret custom fields, removal/clearing, add-copy override, and trash. |
| `view`, `search` | Vault list and Tools → Advanced search: all text/field/type/authenticator/weak/stale filters and sort fields/direction. |
| `get` | Item details: reveal/copy primary secret or individual custom fields; reveal protected values explicitly. |
| `history`, `restore-password` | Tools → Password history: select an item, load revisions, restore a revision. |
| `trash`, `restore`, `purge` | Tools → Deleted items: restore, erase one, or empty trash with confirmation. |
| `audit` | Tools → Vault health: stale threshold, breach lookup, and missing authenticator checks. |
| `totp` | Item authenticator controls: set/remove, Duo passcode enrollment and mode, show/copy, timeout override, TOTP watch and copy-on-refresh. HOTP advances only on explicit requests. |
| `duo` | Item authenticator controls: enroll/replace/mode, fetch/watch/interval/notifications, review and approve/deny an exact request, Verified Push code, remove enrollment. |
| `backup`, `import`, `export` | Tools → Import, export & backups: paths, password/key credentials, backup/export replacement, import preview/new vault/conflict policy. `.json` selects portable JSON; other export suffixes select CSV. |
| `native-host` | Tools → Browser integration: Chrome/Chromium/Helium registration and update. The hidden bridge process is started by the browser. |
| `sync` | Settings → Connection → Cloud sync: server URL/device credential, list/select/download vault, download comparison copy, enable/disable/status/check/now, and side-by-side conflict review with per-field resolution. Tokens can be pasted from a credential file instead of supplied via a CLI file argument. |
| `completions` | Tools → CLI utilities: save definitions for all five shells. Existing destination files are protected. |

CLI aliases select the same operation. `--json`, `--quiet`, stdout-only output,
shell dynamic-completion setup, noninteractive `--yes`, and hidden internal or
generated-artifact commands are specific to terminal/process integration. The
desktop provides native presentation, explicit confirmations, and file exports.
Its Connection settings also offer a one-time port override.

Regression tests cover command construction, secret/session handling, settings,
generation, recovery, and completion output. Rendering tests cover native Iced
widget layouts; a full interactive platform acceptance pass remains separate.

## Android feature map

Android calls the shared Rust vault library in process and has separate
device-local settings. Version 0.3.0 uses the following routes:

| Capability | Android route |
| --- | --- |
| Vault selection/create/import/restore | Vault home → Add or restore a vault; Open a local vault selects existing local storage. |
| Items and search | Vault → live search/type filters, Add item, item details → Edit item. Tools → Advanced search adds filters/sorting. |
| Reveal/copy, history, authenticators | Item details → show/copy actions, Password history, Authenticator & Duo. HOTP requires explicit confirmed generation. |
| Generation and health | Tools → Password generator / Vault health; standalone generation is available while locked. |
| Trash and recovery | Tools → Deleted items / Files & backups; imports have preview/policy approval, and file transfers use Android's picker. |
| Credential changes and key files | Tools → Vault credentials; home setup → External-key vault tools. Rekey/deletion require original credentials. |
| Settings and biometrics | Settings → Mobile settings / Biometric unlock. Mobile defaults and ranges differ from desktop `pm config`. |
| Sync | Settings → Cloud sync settings / download vault / Review sync conflicts; Tools → Sync controls for per-vault status, check, enable/disable and explicit synchronization. |
| Browser/system integration | Settings → Enable password autofill; Android 14+ → Enable password and passkey provider. Android autofills passwords/TOTP; desktop card/identity autofill does not imply mobile support. |

Daemon/process administration, desktop shortcut/native-host registration, shell
completions, terminal flags, and desktop watch/notification switches have no
one-to-one mobile route. Android does not run a continuous desktop-style sync
daemon. Passkey data is interoperable, but desktop browser passkey creation and
sign-in remain unimplemented. See the [mobile feature and acceptance matrix](mobile-implementation.md#mobile-feature-parity-roadmap)
for per-capability limits and the [Android user guide](user-guide.md#android-app)
for daily workflows. Implementation is distinct from real provider acceptance.
