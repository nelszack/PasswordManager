# CLI, desktop and Android feature map

All three clients run the same Rust vault code. The CLI and desktop send typed
server commands to the local service. Android sends the same `ServerCommand`s to
the shared library in process (`src/vault/mobile.rs`). Item-type labels and
suggested fields come from one shared table (`src/item_profile.rs`), so a card or
identity created on any client has the field names that card and identity autofill
recognize.

Reviewed against `src/cli.rs`, `src/gui/`, and the Android sources on
2026-11-21. A cell describes what is implemented. It does not mean device
acceptance; see the [mobile acceptance matrix](mobile-implementation.md#mobile-feature-parity-roadmap).

## Shared vault operations

| Capability | CLI | Desktop | Android |
| --- | --- | --- | --- |
| Create, unlock, choose vault | `new`, `unlock`, `vaults` | Vault picker and unlock form | Vault home → Set up / Unlock / Add or restore a vault |
| Add and edit all eight item types | `add`, `update` | Item editor with type-specific labels and suggested fields | Add item / Edit item with the same type labels and suggested fields |
| Websites, notes, custom fields, secret fields | `add`/`update` `--url`, `--field`, `--secret-field`, `--remove-field` | Item editor | Item editor (one website per line; secret/remove per field) |
| Tags and favorites | `--tag`, `--add-tag`, `--remove-tag`, `--favorite` | Editor; star in item details | Editor (comma-separated tags, Favorite) |
| Browse and filter | `list` (alias `view`) with `--type`, `--tag`, `--favorites`, health filters and sort | Vault list: text, type, tag, favorites | Vault list: text, type chips, ★ Favorites, tag picker |
| Advanced search | `search`: text, name, username, URL, notes, type, authenticator, weak, stale, tags, favorites, sort | Tools → Advanced search (all of these) | Tools → Advanced search (all of these) |
| Show and copy secrets | `get`, `--password-only`, `--field`, `--reveal-secrets` | Item details: reveal/copy primary secret and fields | Item details: show/copy password, username, each field |
| Attachments | `attachment` add/save/remove | Item details → Attachments | Item details → Attachments (system file picker) |
| Trash | `delete`, `trash`, `restore`, `purge` | Delete; Tools → Deleted items | Delete item; Tools → Deleted items |
| Password history | `history`, `restore-password` | Tools → Password history | Item → Password history |
| Vault health | `audit` (`--stale-days`, `--require-totp`, `--breaches`) | Tools → Vault health | Tools → Vault health |
| TOTP/HOTP | `totp` set/show/remove/duo | Item authenticator controls | Item → Authenticator & Duo; HOTP needs explicit confirmation |
| Duo Push | `duo` enroll/requests/approve/deny/remove | Item authenticator controls | Authenticator → Duo enrollment & push; Duo shortcut on the vault list |
| Generator and strength check | `genpass`, `passcheck` | Generator | Tools → Password generator (also while locked) |
| Encrypted backups | `backup` create/restore | Tools → Import, export & backups | Tools → Files & backups |
| Import and export | `import` (preview, conflict policy, `--new`), `export` (JSON/CSV) | Tools → Import, export & backups | Tools → Files & backups (preview, conflict policy, JSON/CSV) |
| Change credentials, delete vault | `rekey`, `vaults delete` | Tools → Vault security | Tools → Vault credentials |
| Cloud sync | `sync` connect/vaults/pull [--copy]/enable/disable/status/check/conflicts/resolve/now | Settings → Sync | Settings → Cloud sync settings / download vault and Review sync conflicts; Tools → Sync controls |
| Automatic background sync | `config --sync-automatic` | Settings → Sync checkbox | Syncs on open and after each change (no background service) |
| Preferences | `config` | Settings | Settings → Mobile settings (separate device-local values) |
| Lock | `lock` | Lock | Lock button; also locks on background, screen off and inactivity |

CLI aliases select the same operation. `--json`, `--quiet`, `--yes`, stdout output
and shell dynamic completion are for scripts and terminals only. The desktop and
Android ask for confirmation and save files through a file chooser instead.

## Differences by platform

These exist only where they make sense:

- **Desktop service and terminal** (CLI and desktop): `start`, `status`, `kill`,
  `operation` (Tools → CLI utilities → Check operation outcome), `completions`
  (Tools → CLI utilities), `native-host` (Tools → Browser integration), `gui`
  (`--install-shortcut`: Tools → Browser integration), Connection settings and a
  one-time port override. Android runs no background service, so it has nothing
  to start, stop or recover.
- **Browser passkey confirmation and SSH agent** (CLI and desktop): `passkey`
  approve/deny and PIN (the Vault tab's Confirm it's you banner, Settings →
  Security → Passkey PIN), and `ssh-agent` (Settings → Security switch and socket;
  SSH key requested banner). Android is itself the passkey provider and confirms
  with fingerprint or vault unlock. Phones have no SSH agent. SSH key items still
  carry their "SSH agent" field, so a key added on the phone works with the
  desktop agent.
- **Desktop appearance and scale**: desktop Settings only. Android follows the
  system theme and font size.
- **Live watching**: `totp show --watch` and `duo watch` (`--notify`,
  `--interactive`); the desktop has TOTP watch/copy-on-refresh and Duo watch
  with notifications. Android refreshes the code on the item screen and checks
  Duo when you tap Check again.
- **Per-unlock timeout**: `unlock --timeout` and the desktop unlock form override
  the default for one session. Android always uses the auto-lock preference.
- **Generator ranges** are the same everywhere: 8–255 characters or 3–64 words.
  Android and the browser extension remember your last choice on that device; the
  CLI and desktop start passphrases at 6 words (`genpass --words`).
- **Android only**: biometric unlock, password/card/identity autofill and the
  Android 14+ passkey provider, encrypted vault snapshot export, the
  old-password recovery copy kept during rekey, and an explicit "apply trash
  retention" action (the desktop service purges old trash by itself).

## Tests

Regression tests cover command construction, secret/session handling, settings,
generation, recovery and completion output for the CLI and desktop. Rendering
tests cover native Iced layouts. `every_public_cli_command_has_an_entry_in_the_desktop_feature_map`
fails if a new public CLI command is not listed here. Android host tests in
`src/vault/mobile*.rs` run the bridge requests the app uses, and the Android
instrumentation tests are listed in the
[mobile checklist](mobile-implementation.md#verification-evidence). Interactive
platform acceptance is separate.
