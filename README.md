# Password Manager

A local-first password manager with an Iced desktop GUI, a Rust CLI, and a
Chrome/Chromium browser extension. One `pm` executable provides the GUI, CLI,
and independent background server. Vaults use Argon2id key derivation and
XChaCha20-Poly1305 encryption.

- Store logins, secure notes, payment cards, identities, Wi-Fi credentials,
  software licenses, SSH keys, and API secrets, with multiple URLs and custom fields.
- Generate passwords or passphrases; search, filter, and audit for weak, reused,
  duplicate, stale, or breached passwords and missing authenticators.
- Use TOTP/HOTP codes and experimental Duo passcode and manual Push enrollment.
- Autofill logins, cards, identities, and OTP codes; generate passwords and manage
  vault entries from the extension.
- Recover password history and deleted entries; import/export CSV or portable
  JSON, preview import conflicts and data loss, and create encrypted full-vault backups.
- Keep stable entry IDs, timed clipboard cleanup, and inactivity/system-event locking.

[User guide](docs/user-guide.md) · [Command reference](docs/commands.html) ·
[Contributor guide](docs/development.md) · [Security policy](SECURITY.md)

## Installation

Build with a current stable Rust toolchain and a native C/C++ toolchain
(MSVC on Windows):

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

The shortcut runs the same executable without opening a terminal. Pin it to your
dock or copy the installed `.desktop` file to your desktop if your environment
supports desktop icons. Rerun installation if you move the executable. `pm gui`
also opens the GUI explicitly; `pm --help` shows CLI usage. A GUI build requires
a desktop display only when opening the GUI. For a CLI-only build, use
`cargo build --release --locked --no-default-features`.

The desktop editor supports all item types, public and secret custom fields,
URLs, multiline secrets, and notes. The Tools tab adds the recovery, security,
file, and integration workflows described in the
[desktop guide](docs/user-guide.md#desktop-interface).

For the terminal workflow, existing commands work as before:

```bash
pm start
pm new
pm unlock
pm add --name "Example account" --username alice --url https://example.com
pm view
pm get --entry-name "Example account"
pm lock
```

`pm new` prompts twice for a master password and leaves the new vault locked.
New passwords must be at least 14 characters and pass a predictability check.
Entry secrets are entered through hidden prompts. By default, `get` redacts
secrets in its output and copies the primary secret with timed clipboard cleanup.

Use `pm status` to check the server and `pm kill` to stop it. The server holds
one unlocked vault at a time. With multiple vaults, list IDs with `pm vaults`,
then use `pm unlock --vault-file ID` or configure a default vault.
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

## Browser extension

1. Load `extension/` as an unpacked extension in Chrome, Chromium, or Helium.
2. Copy its ID from `chrome://extensions`, then register the native host:

   ```bash
   pm native-host install --extension-id YOUR_EXTENSION_ID --browser chrome
   ```

   Use `--browser chromium` or `--browser helium` as appropriate, then reload
   the extension. On Windows, fully exit and reopen Helium after registration.
3. Start and unlock the server. Use the key button beside a login field to
   choose an account, or **Open vault manager** in the popup to unlock and manage items.

Autofill and save prompts operate on HTTPS pages. Credentials match saved
origins, including scheme and port; subdomain sharing requires an explicit
wildcard URL. See the [browser guide](docs/user-guide.md#browser-extension) for
matching rules, generator settings, card/identity fields, and recovery after an
uncertain save. [Duo Push](docs/user-guide.md#duo-push) requires separate enrollment
and an explicit decision for each request.

## Configuration

```bash
pm config
pm config --length 24 --clipboard-timeout 30 --unlock-timeout 15m
pm config --password-history-limit 20 --trash-retention-days 30
```

Defaults include a 12-character generated password, 15-second clipboard cleanup,
15-minute inactivity lock, ten password revisions, no trash expiration, and
loopback server port `7878`. Restart the server after changing recovery settings.
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
