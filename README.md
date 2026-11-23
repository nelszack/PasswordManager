# Password Manager

A local-first password manager with an Iced desktop GUI, a Rust CLI, a
Chrome/Chromium/Firefox browser extension, and a native Android app. One desktop `pm`
executable provides the GUI, CLI, and independent background server. The Android
APK embeds the same Rust vault library. Vaults use Argon2id key derivation and
XChaCha20-Poly1305 encryption.

- Store logins, secure notes, payment cards, identities, Wi-Fi credentials,
  software licenses, SSH keys, and API secrets, with multiple URLs and custom fields;
  organize them with tags and favorites, and attach small encrypted files.
- Generate passwords or passphrases; search, filter, and audit for weak, reused,
  duplicate, stale, or breached passwords and missing authenticators.
- Use TOTP/HOTP codes and experimental Duo passcode and manual Push enrollment.
- Serve Ed25519 SSH keys to `ssh` and `git` through a built-in SSH agent
  (Linux and macOS, opt-in).
- Create and use passkeys from the browser extension (ES256, shared with Android).
- Autofill logins, cards, identities, and OTP codes; generate signup passwords
  and save credentials through site-scoped desktop browser prompts. Manage vaults
  in the desktop app, CLI, or Android app; Android autofills passwords, TOTP,
  payment cards, and identities.
- Recover password history and deleted entries; import/export CSV or portable
  JSON, preview import conflicts and data loss, and create encrypted full-vault backups.
- Keep stable entry IDs, timed clipboard cleanup, and inactivity/system-event locking.

[User guide](docs/user-guide.md) · [Command reference](docs/commands.html) ·
[Contributor guide](docs/development.md) · [Security policy](SECURITY.md) ·
[All documentation](docs/README.md)

Android development: [private APK build and setup](android/README.md) ·
[mobile/passkey implementation and device acceptance checklist](docs/mobile-implementation.md).
Android supports 64-bit Android 9+ with Vault/Tools/Settings navigation, live
search, typed editing, recovery tools, encrypted sync, optional fingerprint
unlock, and native password/TOTP/card/identity autofill. Its passkey provider requires Android
14+. Install privately by APK; no store publication is needed. iPhone support
remains planned. See the checklist for implemented features and remaining device
acceptance checks.

## Installation

Build with a current stable Rust toolchain and a native C/C++ toolchain
(MSVC on Windows).

Linux desktop builds also need pkg-config and the Fontconfig/FreeType development
packages (`pkg-config libfontconfig1-dev libfreetype6-dev` on Debian/Ubuntu,
`pkgconf fontconfig freetype2` on Arch). CLI-only builds do not need these packages.

Build the desktop executable with:

```bash
cargo build --release --locked
```

Add `target/release` to `PATH`, or use the full path to `pm` (`pm.exe` on Windows).
Release archives include a prebuilt binary and the extension. Keep the executable
at a stable path before registering the browser native host.

For upgrades, run `pm native-host update` using the new executable, restart the
server, and reload the extension. On Windows, fully close the browser first:
the native host is a copy that must be refreshed **after** rebuilding.
See [installation and upgrade troubleshooting](docs/user-guide.md#installation)
and [shell completions](docs/user-guide.md#shell-completions).

## Quick start

Run `pm` with no arguments to open the desktop vault manager. It starts or connects
to the background server automatically. Create or unlock a vault, search items,
add/edit entries, copy or briefly reveal secrets, and generate passwords or
passphrases. Closing the window leaves the server running for the CLI and extension;
the vault still locks on inactivity and system-lock events.
The Settings tab exposes all `pm config` preferences and reset, sharing the same
configuration with the CLI.
The Tools tab covers history/trash recovery, audits, import/export and encrypted
backups, vault credential changes, advanced search, and browser registration.
Select an account for OTP codes, Duo Push requests, and custom fields; edit it to
manage authenticator and Duo enrollment or multiline secrets.

On Linux, install an application-menu icon after putting `pm` at a stable path:

```bash
pm gui --install-shortcut
```

The shortcut installs the lock icon shared with the browser extension and runs
the same executable without opening a terminal. Rerun the command after upgrading
to refresh the installed icon. Pin it to your dock or copy the installed
`.desktop` file to your desktop if your environment
supports desktop icons. Rerun installation if you move the executable. `pm gui`
also opens the GUI explicitly; `pm --help` shows CLI usage. A GUI build requires
a desktop display only when opening the GUI. For a CLI-only build, use
`cargo build --release --locked --no-default-features`.

On Windows, create a shortcut to `pm.exe`, then open the shortcut's
**Properties → Change Icon → Browse** and select `assets/password-manager.ico`
from the source checkout, or `password-manager.ico` beside `pm.exe` in a release
archive. Keep the icon file at that location so the shortcut can find it.

The desktop editor supports all item types, public and secret custom fields,
URLs, multiline secrets, and notes. The Tools tab adds the recovery, security,
file, and integration workflows described in the
[desktop guide](docs/user-guide.md#desktop-interface).

For the terminal workflow, existing commands work as before:

```bash
pm new --name Personal
pm add --name "Example account" --username alice --url https://example.com
pm view
pm get "Example account" --copy
pm lock
pm unlock
```

`pm new` prompts twice for a master password, names the vault on this device,
and opens it (add `--locked` to leave it locked). New passwords must be at least
14 characters and pass a predictability check. Item secrets are entered through
hidden prompts; scripts can pipe them with `pm --password-stdin …`. `get` hides
secrets in its output and copies the password only with `--copy`, clearing the
clipboard after the configured timeout.

Use `pm status` to check the server and `pm kill` to stop it. The server holds
one unlocked vault at a time. With several vaults, `pm vaults` lists their names
and files; open one with `pm unlock --vault NAME` or configure a default vault.
A key file finds its own vault.
External-key vaults are also supported; keep keys outside application data and
separate from the vault. See [vault creation](docs/user-guide.md#create-your-first-vault).

## Common commands

```bash
pm genpass --length 24 --exclude-ambiguous --copy
pm genpass --passphrase --words 7 --separator "."
pm search github --sort name
pm update --id 3 --password
pm audit --stale-days 365 --require-totp
pm totp set --id 3
pm totp show --id 3 --copy
pm delete --id 3
pm trash
pm restore --id 3
pm backup create --path vault.pmbackup
```

Deletion moves entries to encrypted trash; purging and whole-vault deletion are
permanent. Encrypted backups preserve the complete vault and recovery state.
CSV and portable JSON exports contain **plaintext secrets**; CSV omits OTP/Duo
credentials, and portable JSON includes sensitive authenticator and history data.
Review [backup and import/export guidance](docs/user-guide.md#importexport) before use.

Run `pm <COMMAND> --help` or open the [complete command reference](docs/commands.html)
for flags and examples. The [user guide](docs/user-guide.md) covers typed items,
custom fields, history, rekeying, authenticators, Duo Push, and scripted JSON output.

## Cloud sync

Optional self-hosted sync stores encrypted vault snapshots on a small Go server
and supports downloading existing vaults onto a new device. Install the server
separately, issue a credential per device, and connect with
`pm sync connect https://SERVER --token-file TOKEN_FILE`. Then run
`pm sync enable` for an unlocked vault. See the
[cloud sync setup and current limitations](docs/cloud-sync.md).

## Browser extension

1. Load `extension/` as an unpacked extension in Chrome, Chromium, or Helium.
   For Firefox 128+, build `extension-firefox/` with
   `node scripts/package_extension.cjs --browser firefox DIR` (release archives
   include it), load it, and run `pm native-host install --browser firefox`;
   see [Firefox setup](docs/user-guide.md#firefox).
2. Turn on browser integration in the desktop app (**Settings → Browser &
   service**), or run:

   ```bash
   pm native-host install --browser chrome
   ```

   The extension's ID is fixed by its manifest, so no ID needs copying. Use
   `--browser chromium` or `--browser helium` as appropriate, then reload the
   extension. On Windows, fully exit and reopen Helium after registration.
3. Unlock a vault in the desktop app or CLI. The toolbar popup lists the logins
   saved for the current site, fills one into the page, copies usernames,
   passwords, and one-time codes (the desktop service clears the clipboard
   afterwards), and can save a new login with a generated password. The key
   button beside a login field, or `Ctrl+Shift+L`, opens the secure account
   picker.

Autofill and save prompts operate on HTTPS pages. Credentials match saved
origins, including scheme and port; subdomain sharing requires an explicit
wildcard URL. See the [browser guide](docs/user-guide.md#browser-extension) for
matching rules, signup generation, card/identity fields, and recovery after an
uncertain save. [Duo Push](docs/user-guide.md#duo-push) requires separate enrollment
and an explicit decision for each request.

## Configuration

The following defaults and commands apply to the desktop/CLI service. Android
has independent [mobile preferences](docs/user-guide.md#android-preferences).

```bash
pm config
pm config --length 24 --clipboard-timeout 30 --unlock-timeout 15m
pm config --password-history-limit 20 --trash-retention-days 30
```

Defaults include a 12-character generated password, 15-second clipboard cleanup,
15-minute inactivity lock, ten password revisions, no trash expiration, and
loopback server port `7878`. Restart the server after changing recovery settings (the desktop app offers **Restart service now** under Settings).
Use `pm config --reset` to restore defaults.

On Linux, configuration lives in `~/.config/password_manager` and data in
`~/.local/share/password_manager`, respecting XDG overrides. macOS and Windows
use platform directories. `PM_CONFIG_DIR` and `PM_DATA_DIR` override these paths;
use consistent absolute paths for the CLI, server, and browser native host.
See [configuration details](docs/user-guide.md#configure-settings) and
[data locations](docs/user-guide.md#configuration-and-data-locations).

## Security

See [SECURITY.md](SECURITY.md) for the threat model, security limits, and private
vulnerability-reporting process.

- Master passwords derived using Argon2id with a random salt when a new
  password-encryption key is created
- Vault files use random, password-independent names
- Vaults encrypted and authenticated with XChaCha20-Poly1305
- A versioned, authenticated vault header records the format and exact KDF
  parameters used to derive its cached session key
- Keys derived with BLAKE3
- Zeroize for secure memory cleanup
- Configurable inactivity-based auto-lock timeout; locking clears in-memory
  secrets without depending on disk writes
- Key files must be stored outside application data
- The local server rotates its random session token on every process start and
  requires it for every encrypted local connection; vault, key, and token files use
  owner-only `0600` permissions on Linux/macOS and explicit current-user-only
  ACLs on Windows

Clipboard history can retain secrets, and CLI-generated copies have independent
cleanup timers that server locking does not cancel. See
[clipboard behavior](docs/user-guide.md#clipboard-behavior).

Upgrade the CLI, native host, and extension together. Older development vault
formats require a verified portable export/import using the original binary;
there is no automatic migration. If a mutation reports an uncertain outcome,
inspect vault state before retrying.

## Contributing

Run the shared Rust and extension validation from the repository root
(Node.js 26.7 or newer):

```bash
npm ci
npm run validate
```

The [contributor guide](docs/development.md) covers architecture, browser tests,
coverage, generated extension bundles and command contracts, and manual release
packaging. See the [fuzzing guide](fuzz/README.md) for fuzz targets and reproduction.

Android builds, JVM tests/lint, and isolated emulator/phone checks are separate;
follow [Android development](docs/development.md#android-development).

## Third-party assets

The desktop app's icons come from a small subset of Google's
[Material Icons](https://github.com/google/material-design-icons)
(`assets/material-icons.ttf`), used under the Apache License 2.0; see
`assets/LICENSE-material-icons.txt`. `scripts/subset_icon_font.py` regenerates the
font and `src/gui/icon_chars.rs` together when an icon is added.
