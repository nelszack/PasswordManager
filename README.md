# Password Manager

A secure, local-first password manager with a CLI interface and browser extension.

## Features

- **Secure Storage**: Versioned encrypted vaults using Argon2id and XChaCha20-Poly1305
- **Password Generator**: Random passwords with configurable character sets, or readable passphrases
- **Password Strength Checker**: Evaluate password strength with zxcvbn
- **Security Health**: Score weak, reused, duplicate, stale, breached, and TOTP coverage findings without exposing passwords
- **Recovery**: Bounded password history and encrypted trash with restore/purge controls
- **Search and Filtering**: Case-insensitive searches across non-secret entry fields
- **Typed Items**: Logins, secure notes, payment cards, identities, Wi-Fi,
  software licenses, SSH keys, and API secrets
- **Multiple URLs**: Associate several explicitly approved sites with one login
- **Sorting and Rich Filters**: Sort listings and filter by type, TOTP, or weakness
- **Custom Fields**: Searchable fields and privately prompted secret fields
- **Stable IDs**: Entry IDs remain unchanged when other entries are deleted or restored
- **TOTP Authenticator**: Encrypted per-entry authenticator secrets with current-code generation
- **Browser Extension**: Native-messaging bridge, on-page autofill, TOTP, and save/update prompts
- **In-page Password Generation**: Fill new-password and confirmation fields securely
- **Clipboard Integration**: Secure clipboard with auto-clear timeout
- **Import/Export**: Interoperable CSV plus versioned, full-fidelity portable JSON
- **Import Planning**: Non-mutating previews with skip, replace, and keep-both policies
- **Encrypted Backups**: Versioned, authenticated full-vault backup and disaster recovery
- **Background Server**: Long-running server for quick access

## Installation

```bash
cargo build --release
```

The binary will be at `target/release/pm`.

## Usage

### Start the Server

```bash
pm start
```

The server creates a private session token automatically. CLI and
native-messaging clients read it from the protected application data directory;
it is not displayed to the user or stored in the extension.

### Generate a Password

```bash
pm genpass --length 20 --copy
pm genpass --length 24 --exclude-ambiguous --no-symbols
pm genpass --passphrase --words 7 --separator "."
```

Character classes can be disabled with `--no-uppercase`, `--no-lowercase`,
`--no-digits`, and `--no-symbols`; replace the default symbol set with
`--symbols`. At least one non-empty class must remain.

### Add a New Entry

```bash
pm add --name "github.com" --username "user@email.com" --generate-password --copy
```

Login items are the default. Repeat `--url` to associate several sites with the
same login; the first URL is primary and every additional URL participates in
search and browser-extension matching:

```bash
pm add --name "Example account" --username alice \
  --url https://example.com --url https://accounts.example.net
```

Other encrypted item types use the same compact field model: `--name` is the
display name, `--username` is an optional account/owner identifier, the hidden
password prompt stores the primary secret, and `--notes` stores supporting
details. Identity items have no primary-secret prompt.

```bash
pm add --type secure-note --name "Alarm code"
pm add --type payment-card --name "Personal Visa" --username "Alice Example"
pm add --type identity --name "Shipping identity" --username "alice@example.com" --notes "Home address"
pm add --type wifi --name "Office Wi-Fi" --username WPA3
pm add --type software-license --name "Design app" --username "Alice Example"
pm add --type ssh-key --name "Production SSH" --username deploy
pm add --type api-secret --name "Deployment API" --username key-id-123
```

For secure notes the primary secret is the note body; for cards it is the card
number; for Wi-Fi it is the network password; and for licenses, SSH, and API
items it is the corresponding key or secret. These values are read through the
hidden prompt and handled like login passwords.

Add searchable custom fields with `--field NAME=VALUE`. For sensitive values,
use `--secret-field NAME`; the value is read through a hidden prompt and is not
included in search results or ordinary listings:

```bash
pm add --name "Hosting" --field environment=production --secret-field recovery-code
```

### View All Entries

```bash
pm view
```

Listings can be sorted by stable ID, name, creation time, modification time, or
password age. Add `--descending` to reverse the selected order:

```bash
pm view --sort name
pm view --sort modified --descending
pm view --sort password-age
```

### Search and Filter Entries

Search across names, usernames, URLs, and notes (passwords are never searched):

```bash
pm search github
pm search --username alice --url github.com
pm search work --name git --notes account
pm search --type wifi
pm search --totp --sort name
pm search --weak --sort password-age
pm search --stale-days 365 --sort password-age
```

The general search term matches any non-secret field. Field-specific filters are
combined, so every supplied filter must match. Matching is case-insensitive.
The `--type`, `--totp`, `--no-totp`, `--weak`, and `--stale-days` filters work with both
`view` and `search`. Supported types are `login`, `secure-note`,
`payment-card`, `identity`, `wifi`, `software-license`, `ssh-key`, and
`api-secret`. Weakness filtering ignores items with no primary secret.

### Get a Password

```bash
pm get --entry-name "github.com"
```

### Update an Entry

```bash
pm update --name "New Name" --entry-name "github.com"
```

Item types and URL associations can be changed without altering the secret:

```bash
pm update --id 3 --type login
pm update --id 3 --add-url https://login.example.net
pm update --id 3 --remove-url https://old.example.com
pm update --id 3 --clear-urls
pm update --id 3 --field environment=staging
pm update --id 3 --secret-field api-token
pm update --id 3 --remove-field environment
pm update --id 3 --clear-fields
```

### Delete an Entry

```bash
pm delete --entry-name "github.com"
```

Deletion moves the entry and its password history into encrypted trash. Manage
deleted entries with:

```bash
pm trash
pm restore --id 1
pm purge --id 1
pm purge --all
```

`restore` and `purge --id` use the IDs shown by `pm trash`. Purging is
permanent.

Trash retention can optionally purge old items whenever a vault is unlocked.
It is disabled by default; configure a number of days to enable it.

Active entry IDs are persistent: deleting or restoring a different entry does
not renumber them. Restoring a trashed entry also restores its original ID, and
imports receive new local IDs instead of trusting IDs from the source file.

### Password History

Changing a password retains previous passwords inside the encrypted vault. The
default limit is ten revisions and can be configured or set to zero to disable
new history. History output shows timestamps, not password values:

```bash
pm history --entry-name "github.com"
pm restore-password --entry-name "github.com" --revision 1
```

Revision `1` is the newest previous password. Restoring a revision places the
current password back into history, so the operation can be reversed.

### Audit the Vault

```bash
pm audit
pm audit --stale-days 365 --require-totp
pm audit --breaches
```

The audit assigns a health score and checks active logins for weak passwords,
reused-password groups, and duplicate site/username combinations. Optional
checks report passwords older than a chosen number of days and accounts without
TOTP. Reports identify affected entries but never print their passwords.

`--breaches` performs an opt-in Pwned Passwords range check. It sends only the
first five characters of each password's SHA-1 hash, requests padded responses,
and never sends a password or complete hash. The ordinary audit remains fully
offline. A network failure is reported without suppressing the local results.

### TOTP Authenticator

Paste either a Base32 authenticator secret or a complete `otpauth://totp/...`
URI into the hidden setup prompt:

```bash
pm totp set --entry-name "github.com"
pm totp show --entry-name "github.com"
pm totp show --id 3 --copy --copy-time 20
pm totp remove --id 3
```

The output includes the current code and its remaining validity. Raw Base32
secrets use the standard SHA-1, six-digit, 30-second configuration; OTPAuth
URIs can specify their algorithm, digits, and period. Correct system time is
required for valid codes. Entry and trash listings mark configured accounts
with `[TOTP]` without revealing their authenticator secrets.

RFC 4226 specifies a 128-bit minimum secret and recommends 160 bits. Some
providers, including GitHub, issue 80-bit secrets for compatibility. Provider
secrets from 80 bits upward are accepted, with a warning below 128 bits;
shorter secrets remain rejected.

Authenticator configurations are stored only inside the encrypted vault. They
remain attached to an entry in trash and after restoration, and are securely
removed when that trash entry is purged. Plaintext CSV exports omit authenticator
configurations and richer item metadata. Portable JSON exports preserve active
item metadata, history, and TOTP configurations; use an encrypted backup when
trash and the complete recovery state must also be preserved.

### Lock/Unlock

```bash
pm lock
pm unlock --timeout 15m
```

The timeout is based on inactivity: each authenticated vault operation resets it;
passive status polling does not.
Durations accept seconds or `s`, `m`, `h`, and `d` suffixes. New configurations
default to 15 minutes; a value of `0` disables automatic locking.

### Change the Master Password or Key File

Unlock the vault first, then run:

```bash
# Prompt for and confirm a new master password
pm rekey

# Or create and switch to a new key file in the application data directory
pm rekey --key replacement.key
```

Rekeying persists the replacement vault before removing the old
vault. An old key file is left in place, but no vault remains encrypted with it.

### Import/Export

For a complete backup that preserves entries, stable IDs, item types, additional
URLs, custom fields, password-age metadata, password history, trash, and TOTP
configurations, use the encrypted backup commands:

```bash
# Prompts for and confirms an independent backup password
pm backup create --path vault.pmbackup

# Existing files are protected unless replacement is explicit
pm backup create --path vault.pmbackup --force

# The server must be running with the current vault locked
pm lock
pm backup restore --path vault.pmbackup
pm unlock
```

Use `--key backup.key` on both commands to use an existing key file from the
application data directory instead of a password. Keep that key separately;
it is not embedded in the backup. Restore writes the complete backup as the
vault associated with its backup password or key. If that destination vault
already exists, restoration requires `--force`.

Backup files use a versioned format and XChaCha20-Poly1305 authenticated
encryption with a fresh nonce and, for passwords, a fresh Argon2id salt. They
are written atomically with private file permissions. The format contains all
encrypted recovery material and is limited to 128 MiB when restoring.

For interoperability with other password managers, plaintext import/export is
still available:

```bash
pm import --path backup.csv --new
pm export --path backup.csv
pm import --path bitwarden.json --new
pm export --path backup.json
```

Preview an import without creating or changing entries, then choose how exact
name/username/URL conflicts are handled:

```bash
pm import --path backup.csv --preview
pm import --path backup.csv --conflicts skip
pm import --path backup.csv --conflicts replace
pm import --path backup.csv --conflicts keep-both
```

`replace` preserves the existing stable ID and records a changed password in
history. `keep-both` adds a new stable ID and appends an `(imported)` suffix.

The format is detected from the input content; exports use a versioned portable
JSON envelope when the path ends in `.json`, otherwise CSV. Portable JSON
preserves active item types, additional URLs, custom fields, password-age
metadata, bounded password history, and TOTP configurations. Imported IDs are
always remapped to safe local IDs. Supported inputs also include Chrome/Chromium
CSV, Firefox CSV, Bitwarden JSON, and 1Password CSV. Duplicate rows with the same
name, username, and URL are skipped. Both export formats contain plaintext
secrets; portable JSON can also contain TOTP secrets and password history, so
exports should be protected or deleted after use.

### Check Password Strength

```bash
pm passcheck --password "mypassword123"
```

### Configure Settings

```bash
pm config --length 24 --stats true --clipboard-timeout 30 --unlock-timeout 15m
pm config --password-history-limit 20 --trash-retention-days 30
```

Recovery settings are loaded when the server starts. Restart a running server
after changing them. A history limit or trash retention value of `0` disables
that behavior.

### Structured and Scripted Output

Server-backed commands accept global `--json` and `--quiet` flags. JSON output
uses a stable object containing `ok` plus either `output` or `error`. Transport,
vault, and availability failures exit with status 1; CLI or local-input errors
use status 2; missing records use status 3; and conflicts use status 4. Quiet
mode still prints errors. Retrieve only a primary secret without clipboard
activity with `get --password-only`:

```bash
pm --json view --sort name
pm --quiet lock
pm get --id 3 --password-only
```

### Shell Completions

Generate tab completion for your shell:

```bash
# bash
sudo mkdir -p /etc/bash_completion.d
pm completions bash | sudo tee /etc/bash_completion.d/pm > /dev/null

# zsh
pm completions zsh > ~/.zshrc.d/_pm

# fish
pm completions fish > ~/.config/fish/completions/pm.fish

# powershell
pm completions powershell > $PROFILE
```

Or write to a file with `pm completions <shell> --output <path>`. Supported
shells: `bash`, `zsh`, `fish`, `elvish`, `powershell`. You may need to
restart your shell (or `source` the file) for completions to take effect.

If tab still completes filenames instead of commands/flags, the script isn't
being sourced. Check with `type _pm` (or `complete -p pm`), and add an
explicit source line to your `~/.bashrc`:

```bash
echo 'source /etc/bash_completion.d/pm' >> ~/.bashrc
source ~/.bashrc
```

## Browser Extension

1. Build or install `pm` at a stable path, then load the `extension` folder as
   an unpacked extension in Chrome, Chromium, or Helium on Linux, macOS, or
   Windows.
2. Copy its 32-character ID from `chrome://extensions` and register the native
   host:

   ```bash
   pm native-host install --extension-id YOUR_EXTENSION_ID --browser chrome
   ```

   Use `--browser chromium` for Chromium or `--browser helium` for Helium.
   Reload the extension after installing the host.

   **Windows Helium note:** Helium currently does not detect the registry
   location written by `--browser helium`. Register it through Helium's
   Chromium-compatible location instead:

   ```powershell
   pm native-host install --extension-id YOUR_EXTENSION_ID --browser chromium
   ```

   Fully exit Helium, including any background processes, and reopen it after
   running the command.
3. Start and unlock the password-manager server.
4. Visit a login page and use the key button beside a credential field to
   choose an account. The extension can offer to save or update credentials
   when a login is submitted.

The service worker talks to `com.myproject.password_manager` through Chrome's
native-messaging API. Chrome launches the registered `pm-native-host` link,
which forwards a small, validated command set to the authenticated local
server. The extension no longer requests localhost access or stores the server
session token. On Linux and macOS the installer creates a host link and writes
the browser manifest in the browser's per-user application-support directory.
On Windows it installs `pm-native-host.exe` and registers the manifest under
the current user's browser registry key, so administrator rights are not
required. If the `pm` executable moves or is upgraded on Windows, rerun the
install command.

Autofill is form-aware: choosing an account fills only the username and current
password fields associated with that control. Other login forms and
new/confirmation-password fields on the page are left unchanged. Forms created
or revealed after page load are detected automatically.

New-password fields receive a generator button. It creates a 20-character
password locally with the browser's cryptographic random-number generator and
fills matching new/confirmation fields. The generated value is not sent across
the extension bridge unless the user submits and chooses to save it.

For entries configured with TOTP, the extension also places an authenticator
button beside fields marked `autocomplete="one-time-code"` or clearly labelled
as OTP/2FA verification fields. Choose the account to fetch and fill a current
code. Only the generated code and its remaining lifetime are returned to the
extension; the encrypted TOTP secret never leaves the vault server.

Credentials are matched to the exact saved hostname by default and are only
retrieved when the picker is opened or a user-initiated login must be checked.
To deliberately share an entry with subdomains, store its URL as a wildcard,
for example `*.example.com`. Wildcards rooted at public suffixes such as
`*.github.io` are rejected for matching.

The badge and any open popup track native-host, server, and vault lock state
continuously, including changes made through the CLI and automatic locking.
The popup can lock the vault; entry management happens through the CLI and
on-page controls.

## Architecture

- `src/main.rs` - CLI entry point and command routing
- `src/server.rs` - Background server for extension communication
- `src/client.rs` - Client for server communication
- `src/native_messaging.rs` - Chrome native host protocol and registration
- `src/vault.rs` - Vault management and storage
- `src/encryption.rs` - Encryption/decryption utilities
- `src/password.rs` - Password generation and strength checking
- `src/cli.rs` - CLI argument parsing
- `src/config.rs` - Configuration management
- `src/clipboard.rs` - Clipboard operations
- `src/file.rs` - File import/export
- `extension/` - Browser extension (Chrome/Chromium)

## Security

- Master passwords derived using Argon2id with a random salt on every vault write
- Vaults encrypted and authenticated with XChaCha20-Poly1305
- A versioned, authenticated vault header records the format and KDF parameters
- Keys derived with BLAKE3
- Zeroize for secure memory cleanup
- Configurable inactivity-based auto-lock timeout
- The local server requires a random session token on every TCP and HTTP
  connection; vault, key and token files use owner-only `0600` permissions on
  Linux/macOS and the current user's application-data directories on Windows

Existing unversioned vaults remain readable. The next successful vault write
automatically stores them in the versioned format.

## Testing

Run the complete unit, protocol-integration, and security regression suite with:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

The suite covers authenticated TCP and HTTP framing, native-message validation,
encrypted backup recovery and tamper detection, hostile encryption parameters,
secret redaction, vault recovery state, TOTP vectors, URL matching, and
plaintext import/export compatibility. GitHub Actions runs the full test and
strict-lint suite on Linux, macOS, and Windows for every push and pull request.

Dependency changes are scanned against the RustSec advisory database and
reviewed on pull requests. Dependabot checks Rust crates and GitHub Actions
weekly. GitHub's secret scanning and push protection remain enabled for the
repository.

## Releases

Releases are never published automatically. First push a semantic-version tag
matching the version in `Cargo.toml`, for example:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Then open the **Release** workflow in GitHub Actions, choose **Run workflow**,
and enter that existing tag. The pipeline reruns tests and strict linting, then
creates a **draft** release with archives for Linux x86-64, Windows x86-64,
macOS Apple Silicon, and macOS Intel. Review the draft and publish it manually
from GitHub's Releases page.

Each archive contains `pm`, the browser extension, README, and shell
completions. Draft releases include generated notes, SHA-256 checksums, and
GitHub build-provenance attestations. Prerelease tags such as
`v0.2.0-beta.1` are marked as prereleases, but still remain drafts until you
publish them.
