# Password Manager

See the browser-friendly [complete command and flag reference](docs/commands.html)
for command descriptions, usage, and flags. Run `pm <COMMAND> --help` for
terminal help and available examples.

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
- **Browser Extension**: Login, payment-card, identity, and TOTP autofill with save/update prompts
- **In-page Password Generation**: Fill new-password and confirmation fields securely
- **Clipboard Integration**: Prompt copy completion, coordinated auto-clear, and lock cleanup
- **Import/Export**: Interoperable CSV plus versioned, full-fidelity portable JSON
- **Import Planning**: Non-mutating previews with skip, replace, and keep-both policies
- **Encrypted Backups**: Versioned, authenticated full-vault backup and disaster recovery
- **Background Server**: Long-running server for quick access

## Installation

Build from the repository root with a current stable Rust toolchain and a native
C/C++ build toolchain (MSVC on Windows):

```bash
cargo build --release --locked
```

The binary will be at `target/release/pm` (`target/release/pm.exe` on Windows).
Add that directory to your `PATH`, or use the full executable path in the
commands below. Release archives include a prebuilt binary and the extension;
keep the binary at a stable path before registering the browser native host.

Building does not change shell completions or browser native-host registrations.
Use `pm completions` to generate a completion file as described in
[Shell Completions](#shell-completions), and register the native host once with
`pm native-host install` as described in [Browser Extension](#browser-extension).

After upgrading, run the intended executable explicitly to update an existing
native host while preserving browser manifests and approved extension IDs:

```bash
./target/release/pm native-host update
```

Unix hosts link to that executable. Windows copies it to the registered host;
fully close the browser, including background processes, before updating.
Restart the server and reload the extension after upgrading. Regenerate any
installed shell completions with `pm completions` to pick up new commands.

If a Windows build fails with `failed to remove file ...\\target\\release\\pm.exe`,
a running process is holding the build executable open. Older native-host
launchers ran that executable directly. Fully exit the browser, including its
background processes, and stop the server with `.\target\release\pm.exe kill`.
Then build and replace the old launcher with the current copied host:

```powershell
cargo build --release --locked
.\target\release\pm.exe native-host update
```

Reopen the browser after updating. The copied Windows native host allows future
builds while the browser is open. A server started from `target\release\pm.exe`
still needs to be stopped with `pm kill` before rebuilding that executable.

## Usage

### Create Your First Vault

```bash
pm start
pm new
pm unlock
pm add --name "Example account" --username alice --url https://example.com
pm view
pm lock
```

`pm new` prompts twice for a master password, creates an empty vault, and leaves
it locked. New master passwords must contain at least 14 characters and pass a
predictability check. Use `pm unlock` before adding or reading entries.

For a vault protected by an external key instead:

```bash
pm start
mkdir -p ./keys
pm new --key ./keys/vault.key
pm unlock --key ./keys/vault.key
```

The key's parent directory must exist. The new key path must not already exist
and must be outside the application data directory. Keep the key separately from the vault. `pm init` and `pm create` are
aliases for `pm new`. Creating another vault locks the currently open vault.

### Start the Server

```bash
pm start
```

The server creates a new private session token on every start. CLI and
native-messaging clients read it from the protected application data directory;
it is not displayed to the user or stored in the extension. A clean shutdown
removes the token file. Before any command is sent, the server proves possession
of that token with a fresh challenge. Commands and responses are then protected
with direction-specific XChaCha20-Poly1305 session keys.

Check the server with `pm status`; stop it with `pm kill`. The server holds one
unlocked vault at a time. Lock it before unlocking a different vault.

### Generate a Password

```bash
pm genpass --length 20 --copy
pm genpass --length 24 --exclude-ambiguous --no-symbols
pm genpass --passphrase --words 7 --separator "."
```

Character classes can be disabled with `--no-uppercase`, `--no-lowercase`,
`--no-digits`, and `--no-symbols`; replace the default symbol set with
`--symbols`. Lengths and passphrase word counts must be at least one, and at
least one non-empty character class must remain. Character-set flags cannot be
combined with passphrase generation.

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
searched or displayed in ordinary listings (field names remain visible):

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

Date sorting compares actual timestamps across time zones and supported formats.
Entries with unrecognized dates sort first in ascending order and last in
descending order.

### Search and Filter Entries

Search across names, usernames, all associated URLs, notes, custom-field names,
and non-secret custom-field values (passwords and secret field values are never
searched):

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
`api-secret`. TOTP and weakness filters apply across item types; `--no-totp`
also includes non-login items without authenticators. Add `--type login` to limit
these filters to accounts. Weakness filtering ignores items with no primary
secret and selects zxcvbn scores of 0–2.

Vault writes enforce the same 128 MiB encrypted-file limit used during unlock.
An operation that exceeds the limit fails before replacement and rolls back its
in-memory changes.

### Get a Password

```bash
pm get --entry-name "github.com"
```

`get` prints item details with the primary secret, notes, and secret custom fields
redacted. It copies a non-empty primary secret when the clipboard timeout is
nonzero. Use `--password-only` to print just the primary secret without copying.
Use `--reveal-secrets` to display secret custom-field values, or `--field NAME`
to print one custom field by its case-insensitive name. Add `--copy` to copy that
field without printing its value; this requires a nonzero clipboard timeout and
reports clipboard failures. These field options do not copy the primary secret.
`--json` wraps the same output and respects the selected reveal option.

```bash
pm get --id 3 --reveal-secrets
pm get --id 3 --field recovery-code
pm get --id 3 --field recovery-code --copy
```

### Update an Entry

```bash
pm update --name "New Name" --entry-name "github.com"
```

Change the primary secret through a hidden prompt, or generate a replacement:

```bash
pm update --id 3 --password
pm update --id 3 --password --generate-password
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

`restore` and `purge --id` use the **1-based positions** shown by the latest
`pm trash` listing, rather than active entries' stable IDs. These positions change
when trash items are restored or purged; list the trash again before selecting
another item. Purging is permanent.

Trash retention can optionally purge old items whenever a vault is unlocked.
It is disabled by default; configure a number of days to enable it.

Active entry IDs are persistent: deleting or restoring a different entry does
not renumber them. Restoring a trashed entry also restores its original ID, and
imports receive new local IDs instead of trusting IDs from the source file.

To permanently delete an entire vault, supply its password or key:

```bash
# Prompt for the vault's master password
pm delete --vault

# Delete a key-based vault and its key file
pm delete --vault --key ./keys/vault.key

# Delete the vault but intentionally retain a shared or backup key
pm delete --vault --key ./keys/vault.key --keep-key
```

Whole-vault deletion cannot be restored. A supplied key file is removed only
after it has successfully opened the matching vault and that vault has been
deleted.

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
offline. Network failures retain both local results and successful
breach findings, identify entries with unchecked breach status, and return a
failure exit status to indicate an incomplete audit. Up to eight requests run
concurrently with a 15-second request timeout and a four-minute overall deadline.

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

To avoid trying every vault's password KDF, list the opaque vault IDs and select
one explicitly. Listing works without a running server and does not decrypt files:

```bash
pm vaults
pm unlock --vault-file 0123456789abcdef0123456789abcdef.enc
pm unlock --vault-file 0123456789abcdef0123456789abcdef.enc --key ./keys/vault.key
```

The selector accepts one `.enc` filename from the application data directory.
Missing files, unreadable keys, invalid headers, unsupported versions, and invalid
authenticated records produce specific errors. A wrong password and modified
ciphertext cannot be distinguished by authentication alone. Omitting the selector
retains automatic vault discovery.

The timeout is based on inactivity: each authenticated vault operation resets it;
passive status polling does not.
Durations accept seconds or `s`, `m`, `h`, and `d` suffixes. New configurations
default to 15 minutes; a value of `0` disables automatic locking.
Locking clears vault memory without depending on storage writes. If automatic
clipboard cleanup fails, `pm status` reports a warning and the extension shows a
warning badge; the vault itself is already locked.

### Change the Master Password or Key File

Unlock the vault first, then run:

```bash
# Prompt for and confirm a new master password
pm rekey

# Or create and switch to a new external key file
pm rekey --key /secure/removable-media/replacement.key
```

New vault, rekey, import, and backup passwords must contain at least 14
characters and pass a predictability check.

Existing key files must be regular files no larger than 1 MiB. Generated key
files contain 32 random bytes.

New key files must be outside the application data directory, so copying the
encrypted vault does not also copy its key. Relative paths are resolved from
the directory where `pm` is run.

Rekeying atomically replaces the ciphertext at the same random vault filename.
There is one vault file throughout the operation. An old key file is left in place,
but the successfully rekeyed vault no longer uses it. If replacement completes but
directory synchronization fails, the new key remains active and the command
reports that durability is uncertain. Keep both credentials until the operation
succeeds durably; after an interruption, verify which credential opens the vault.
Historical backups and filesystem snapshots still use their original credentials.

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

Use `--key /absolute/path/to/backup.key` on both commands to use an existing
external key file instead of a password. Keep that key separately; it is not
embedded in the backup. Restore writes the complete backup as the
vault associated with its backup password or key. If that destination vault
already exists, restoration requires `--force`.

Backup files use a versioned format and XChaCha20-Poly1305 authenticated
encryption with a fresh nonce and, for passwords, a fresh Argon2id salt. They
are written atomically with private file permissions. The format contains all
encrypted recovery material and is limited to 128 MiB when creating and restoring.

For interoperability with other password managers, plaintext import/export is
still available:

```bash
pm import --path backup.csv --new
pm export --path backup.csv
pm import --path bitwarden.json --new
pm export --path backup.json

# Plaintext exports do not overwrite files unless explicitly requested
pm export --path backup.json --force
```

Preview an import without creating or changing entries, then choose how exact
name/username/URL conflicts are handled:

```bash
pm import --path backup.csv --preview
pm import --path backup.csv --conflicts skip
pm import --path backup.csv --conflicts replace
pm import --path backup.csv --conflicts keep-both
```

Imports and previews against the current vault require it to be unlocked and
leave it unlocked. Use `--new --preview` to preview against an empty vault while
the server's vault is locked. Previews require a running server but do not prompt
for a new vault password or change the current lock state. A completed `--new`
import leaves the new vault locked.
`--key` is used only with `--new`, where it creates the new vault's external key.
Import files are limited to 128 MiB and 100,000 items.

`replace` preserves the existing stable ID and records a changed password in
history, resetting its password age. `keep-both` adds a new stable ID and appends
an `(imported)` suffix.

The format is detected from the input content; exports use a versioned portable
JSON envelope when the path ends in `.json`, otherwise CSV. Portable JSON
preserves active item types, additional URLs, custom fields, password-age
metadata, password history (bounded by the configured limit), and TOTP
configurations. Imported IDs are always remapped to safe local IDs. Supported inputs also include Chrome/Chromium
CSV, Firefox CSV, Bitwarden JSON, and 1Password CSV with compatible login columns.
Bitwarden imports include login items only and use their first URI; they do not
import Bitwarden TOTP secrets, custom fields, or other item types. Other CSV/JSON
imports become login items; use this application's portable JSON for rich metadata.
Conflicts compare the exact name, username, and primary URL, including duplicate
rows within one input file. They are skipped by default; `--conflicts` changes
that behavior. Password values are preserved exactly, including whitespace and empty strings; a missing password field is rejected.
Both export formats contain plaintext secrets; portable JSON can also contain
TOTP secrets and password history, so
exports should be protected or deleted after use. Export refuses to replace an
existing file unless `--force` is supplied.

### Check Password Strength

```bash
# Prompt privately (recommended)
pm passcheck

# Explicit arguments are useful for scripts but may remain in shell history
pm passcheck --password "mypassword123"
```

### Configure Settings

```bash
# Display the effective configuration
pm config

pm config --length 24 --stats true --clipboard-timeout 30 --unlock-timeout 15m
pm config --password-copy false
pm config --password-history-limit 20 --trash-retention-days 30
pm config --server-port 8787
```

Recovery settings are loaded when the server starts. Restart a running server
after changing them. A history limit or trash retention value of `0` disables
that behavior.

When an upgrade introduces a new setting, the first command that reads an older
configuration adds the setting to `config.toml` with its current default value.
Existing setting values are preserved.

The server listens only on the loopback interface and uses port `7878` by
default. The setting is stored as `port = 7878` under `[server]` in
`config.toml`. A global flag overrides it for one invocation:

```bash
pm --port 8787 start
pm --port 8787 status
pm --port 8787 kill
```

Pass the same override to every server-backed CLI command. The browser native
host reads the config file, so use `pm config --server-port PORT` instead of a
one-time flag when the extension must use the alternate port. Stop the running
server before changing its configured port, then start it again.

### Configuration and Data Locations

`config.toml` lives in the platform configuration directory; encrypted `.enc`
vaults, the session token, and the native-host installation live in the application
data directory. On Linux these default to `~/.config/password_manager` and
`~/.local/share/password_manager`, respecting `XDG_CONFIG_HOME` and
`XDG_DATA_HOME`. macOS and Windows use platform paths from the `directories` crate.

Set `PM_CONFIG_DIR` and `PM_DATA_DIR` to override the directories. Use absolute
paths and the same values for the server, CLI, and browser-launched native host.
A browser launched outside your shell may not inherit those overrides. Use the
same `PM_DATA_DIR` when installing or updating the native host.

Built-in defaults are a 12-character generated password, no generation statistics,
clipboard copying enabled for generated values and newly added login passwords,
a 15-second clipboard timeout, a 15-minute inactivity timeout, ten password-history
revisions, disabled trash expiration, and server port 7878. `pm config --reset`
restores all defaults. Invalid configuration files produce an error and are left
unchanged.

### Structured and Scripted Output

Public commands accept global `--json` and `--quiet` flags. JSON output
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

Generate or replace a completion file explicitly using the intended installed
executable. Use a separate file for the chosen shell:

```bash
# Bash: bash-completion can load this standard user location
mkdir -p ~/.local/share/bash-completion/completions
pm completions bash --output ~/.local/share/bash-completion/completions/pm

# Zsh: add ~/.zfunc to fpath before running compinit in ~/.zshrc
mkdir -p ~/.zfunc
pm completions zsh --output ~/.zfunc/_pm

# Fish: loaded automatically by Fish
mkdir -p ~/.config/fish/completions
pm completions fish --output ~/.config/fish/completions/pm.fish
```

Create the destination directory first. For PowerShell, generate a separate file
and add a dot-source line to your existing profile:

```powershell
pm completions powershell --output "$HOME/pm-completions.ps1"
# Add this line to $PROFILE:
. "$HOME/pm-completions.ps1"
```

Supported shells are `bash`, `zsh`, `fish`, `elvish`, and `powershell`. Omitting
`--output` or using `--output -` writes to standard output. Reload your shell after
setup. If Bash still completes filenames, check `complete -p pm` and source the
file from `~/.bashrc`:

```bash
source ~/.local/share/bash-completion/completions/pm
```

## Browser Extension

The browser extension injects credential-handling code only into HTTPS pages.
It does not offer autofill or save prompts on plaintext HTTP pages.

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

   On Windows, `--browser helium` automatically uses Helium's
   Chromium-compatible native-messaging registry location. Fully exit Helium,
   including any background processes, and reopen it after registration.
3. Start and unlock the password-manager server.
4. Visit a login page and use the key button beside a credential field to
   choose an account. The extension can offer to save or update credentials
   when a login is submitted.

The service worker talks to `com.myproject.password_manager` through Chrome's
native-messaging API. The browser launches the registered native-host executable,
which forwards a small, validated command set to the authenticated local
server. The extension no longer requests localhost access or stores the server
session token. Page origins are derived from trusted browser sender metadata;
content scripts cannot select a different vault origin or request a TOTP code
for an unrelated entry. Pending save prompts are held briefly in service-worker
session storage and are isolated by tab and origin. On Linux and macOS the
installer creates a host link and writes
the browser manifest in the browser's per-user application-support directory.
On Windows it installs `pm-native-host.exe` and registers the manifest under
the current user's browser registry key, so administrator rights are not
required. Unix registrations link to the executable; Windows registration
copies it. If you move the executable or install a new release binary, run
`pm native-host update` using the new executable. This preserves browser
manifests and approved extension IDs. On Windows, fully close the browser first.

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

Payment-card and identity fields also receive contextual picker buttons. The
actual selection happens in a separate extension-owned window that the webpage
cannot inspect or restyle. Only secret-free labels enter that window; after the
user selects one, the extension retrieves that single item from the unlocked
vault and fills controls in the same form. Locking or losing the native-host
connection invalidates open pickers. The picker displays the receiving site;
for an embedded frame from a different origin, it also displays the main page
and requires explicit confirmation before filling. The extension uses the
browser's `tabs` permission to read the main page's URL for this destination
check. Cardholder/email fall back to the item's `--username`, and the card
number comes from the card item's primary secret. Other values are read from
custom fields using common names, for example:

```bash
pm add --type payment-card --name "Personal Visa" --username "Alice Example" \
  --field "expiration month=09" --field "expiration year=2030" --secret-field cvv

pm add --type identity --name "Home identity" --username alice@example.com \
  --field "full name=Alice Example" --field "address line 1=123 Main St" \
  --field city=Boise --field state=Idaho --field "postal code=83702" \
  --field country=US --field "phone number=2085550100"
```

Supported standard browser fields include cardholder name, card number,
expiration, security code, name components, email, telephone, organization,
street-address lines, city, state/region, country, and postal code. Select boxes
are matched using either their option value or visible label. Payment and
identity secrets are never requested merely because a page loaded.

Credentials match the normalized saved origin: scheme, hostname, and port.
Bare domains mean HTTPS on port 443. Different ports and HTTP/HTTPS origins
require separate saved URLs. To deliberately share an entry with subdomains,
store its URL as a wildcard, such as `https://*.example.com:8443`; the scheme
and port must still match. Public-suffix wildcards such as `*.com`, `*.co.uk`,
and `*.github.io`, URLs with credentials, backslashes, and control characters
are rejected for matching. Existing ambiguous URLs remain stored but must be
corrected before browser filling can use them.

Save/update prompts use account summaries and never compare stored passwords
in a content script. They run after user interaction without delaying or
replaying the site's submission. A prompt may also appear for an already saved
account; cancel it when no update is needed. Script-driven submissions without
user activation do not request account information.

Terminal displays escape control characters in entry metadata. Explicit raw
secret output to a pipe and plaintext exports preserve the stored values.

The badge and any open popup track native-host, server, and vault lock state
continuously, including changes made through the CLI and automatic locking.
They also show a warning when the extension release, installed native host,
and running password-manager server are not the same version. Restart the
server and reinstall/reload the extension after an upgrade to clear it.
The popup can lock the vault; entry management happens through the CLI and
on-page controls.

## Architecture

- `src/main.rs` - CLI entry point and command routing
- `src/server.rs` and `src/server/` - Authenticated local server, command handling, and output rendering
- `src/client.rs` - Client for server communication
- `src/native_messaging.rs` - Chrome native host protocol and registration
- `src/vault.rs` and `src/vault/` - Vault records, mutations, recovery, import/export, and persistence
- `src/encryption.rs` - Encryption/decryption utilities
- `src/password.rs` - Password generation and strength checking
- `src/cli.rs` - CLI argument parsing
- `src/config.rs` - Configuration management
- `src/clipboard.rs` - Clipboard operations
- `src/file.rs` - Application paths, key-path validation, private permissions, and atomic file writes
- `src/protocol.rs` - Authenticated encrypted local transport
- `src/lib.rs` - Shared production library used by the CLI and fuzz harness
- `docs/commands.html` - Browser-friendly CLI reference generated from Clap metadata
- `docs/commands.template.html` - Static layout used by the command-reference generator
- `extension/` - Browser extension (Chrome/Chromium)

### Clipboard behavior

CLI copies return after the clipboard is set, without waiting through the timeout.
A detached helper holds the clipboard until cleanup; secrets travel over stdin,
never command-line arguments. Server copies share one worker, and copying again
replaces its owned value and resets its deadline. Explicit and inactivity locking
clear the latest server-owned copy immediately. Cleanup preserves text copied by
another application. A timeout of `0` disables copying, as before.

Clipboard history managers may retain copies. CLI-generated copies have independent
timeouts and are not canceled by server locking. See [SECURITY.md](SECURITY.md)
for the threat model and limits.

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

## Testing

Run Rust and extension unit checks from the repository root:

```bash
cargo fmt --all -- --check
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
npm ci
npm run test:extension
npm run test:extension:coverage
```

The extension coverage command requires Node.js 26.7 or newer. CI uses Node 26
for coverage and Node 22 for browser end-to-end tests.

Browser tests launch headed Chromium and require a graphical session. The
real native-host/server integration test runs on Linux and requires the binary
at `target/debug/pm`; it is skipped if the binary is missing. Set up and run on
Linux with:

```bash
cargo build --locked
npx playwright install --with-deps chromium
npm run test:e2e:coverage
# On Linux without a graphical session (requires Xvfb):
xvfb-run --auto-servernum npm run test:e2e:coverage
```

The coverage command writes reports under `test-results/e2e-coverage`; use
`npm run test:e2e` to run without coverage collection. Browser tests use temporary
profiles and synthetic vaults. Most fixtures enable HTTP in a temporary extension
copy; production injection remains HTTPS-only.

For Rust coverage, install the LLVM tools and coverage runner first:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
cargo llvm-cov --locked --all-features --workspace --fail-under-lines 65
```

After changing CLI commands or flags, regenerate and verify the browser command
reference with:

```bash
cargo run -- generate-command-reference
cargo run -- generate-command-reference --check
```

The suite covers authenticated encrypted transport, native-message validation,
encrypted backup recovery and tamper detection, hostile encryption parameters,
secret redaction, vault recovery state, TOTP vectors, URL matching, and
plaintext import/export compatibility. GitHub Actions runs the full test and
strict-lint suite on Linux, macOS, and Windows for pushes to `main` and pull
requests. Browser end-to-end and coverage jobs run separately on Linux.

Dependency changes are scanned against the RustSec advisory database and
reviewed on pull requests. Dependabot checks Rust crates and GitHub Actions
weekly, including npm browser-test dependencies and the fuzz harness. Scheduled
security checks audit the Rust and npm lockfiles, including the fuzz lockfile.
Repository secret-scanning and push-protection settings are managed separately
from the checked-in workflows.

Coverage-guided fuzz targets and scheduled CI sessions exercise encrypted headers,
native messages, and import parsers. See [fuzz/README.md](fuzz/README.md) for local
setup, synthetic seeds, and reproducing findings. The CLI and fuzzers share the
production implementation through `src/lib.rs`.

Vault persistence tests distinguish failures before atomic replacement from
failures afterward. The latter retain committed memory and keys and report
uncertain durability, so callers should inspect state before retrying a mutation.

## Releases

Releases are never published automatically. First push a semantic-version tag
matching the version in `Cargo.toml`, for example:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The CLI/package version in `Cargo.toml` is the release version and must match
the browser manifest's `version_name`, which is used for runtime compatibility
checks. The manifest's numeric `version` remains an independent extension-package
revision because browser stores require monotonically increasing revisions.

Then open the **Release** workflow in GitHub Actions, choose **Run workflow**,
and enter that existing tag. The pipeline reruns tests and strict linting, then
creates a **draft** release with archives for Linux x86-64, Windows x86-64,
macOS Apple Silicon, and macOS Intel. Review the draft and publish it manually
from GitHub's Releases page.

Each archive contains `pm`, the browser extension, README, security policy, command
reference, fuzzing guide, and shell completions. Draft releases include generated notes, SHA-256 checksums, and
GitHub build-provenance attestations. Prerelease tags such as
`v0.2.0-beta.1` are marked as prereleases, but still remain drafts until you
publish them.

## Development

Vault logic lives in `src/vault/`, grouped by entries, queries, recovery, TOTP,
imports, exports, backups, and persistence. Read operations return domain records;
`src/server/presentation.rs` renders CLI output, and `src/server/response.rs`
handles protocol delivery and maps domain errors to response codes. Native clients
use structured server status; the CLI retains its human-readable status output.

Vault mutations share `src/vault/transaction.rs`. Individual edits snapshot only
the affected entry and recovery records; imports snapshot the full state. A
failure before atomic replacement restores the snapshot; a directory-sync failure
after replacement keeps committed memory and keys and reports uncertain durability.
Temporary secrets are wiped on drop. Import previews and execution share a plan
based on non-secret fields.

The extension's `content.js` initializes the page integration. The manifest loads
separate scripts for messaging, controls, password generation, typed autofill,
DOM observation, and credential capture, in the same isolated browser world.

See [Testing](#testing) for prerequisites and the checks used by CI.
