# Password Manager

A secure, local-first password manager with a CLI interface and browser extension.

## Features

- **Secure Storage**: Versioned encrypted vaults using Argon2id and XChaCha20-Poly1305
- **Password Generator**: Random passwords with configurable character sets, or readable passphrases
- **Password Strength Checker**: Evaluate password strength with zxcvbn
- **Security Audit**: Find weak, reused, and duplicate active logins without exposing passwords
- **Recovery**: Bounded password history and encrypted trash with restore/purge controls
- **Search and Filtering**: Case-insensitive searches across non-secret entry fields
- **Stable IDs**: Entry IDs remain unchanged when other entries are deleted or restored
- **TOTP Authenticator**: Encrypted per-entry authenticator secrets with current-code generation
- **Browser Extension**: Native-messaging bridge, on-page autofill, TOTP, and save/update prompts
- **Clipboard Integration**: Secure clipboard with auto-clear timeout
- **Import/Export**: CSV and JSON, including common browser and password-manager exports
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

The server prints the location of its session token file (e.g.
`~/.local/share/password_manager/session.key`). CLI and native-messaging clients
read this protected file automatically; it is never stored in the extension.

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

### View All Entries

```bash
pm view
```

### Search and Filter Entries

Search across names, usernames, URLs, and notes (passwords are never searched):

```bash
pm search github
pm search --username alice --url github.com
pm search work --name git --notes account
```

The general search term matches any non-secret field. Field-specific filters are
combined, so every supplied filter must match. Matching is case-insensitive.

### Get a Password

```bash
pm get --entry-name "github.com"
```

### Update an Entry

```bash
pm update --name "New Name" --entry-name "github.com"
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

Active entry IDs are persistent: deleting or restoring a different entry does
not renumber them. Restoring a trashed entry also restores its original ID, and
imports receive new local IDs instead of trusting IDs from the source file.

### Password History

Changing a password retains the ten most recent previous passwords inside the
encrypted vault. History output shows timestamps, not password values:

```bash
pm history --entry-name "github.com"
pm restore-password --entry-name "github.com" --revision 1
```

Revision `1` is the newest previous password. Restoring a revision places the
current password back into history, so the operation can be reversed.

### Audit the Vault

```bash
pm audit
```

The audit checks active entries for weak passwords, reused-password groups, and
duplicate site/username combinations. Reports identify affected entries but
never print their passwords.

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
removed when that trash entry is purged. Plaintext CSV and JSON exports omit
authenticator configurations.

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

```bash
pm import --path backup.csv --new
pm export --path backup.csv
pm import --path bitwarden.json --new
pm export --path backup.json
```

The format is detected from the input content; exports use JSON when the path
ends in `.json`, otherwise CSV. Supported inputs are this application's CSV or
JSON, Chrome/Chromium CSV, Firefox CSV, Bitwarden JSON, and 1Password CSV.
Duplicate rows with the same name, username, and URL are skipped. Both export
formats contain plaintext passwords and should be protected or deleted after
use.

### Check Password Strength

```bash
pm passcheck --password "mypassword123"
```

### Configure Settings

```bash
pm config --length 24 --stats true --clipboard-timeout 30 --unlock-timeout 15m
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
   an unpacked extension in Chrome.
2. Copy its 32-character ID from `chrome://extensions` and register the native
   host:

   ```bash
   pm native-host install --extension-id YOUR_EXTENSION_ID --browser chrome
   ```

   Use `--browser chromium` for Chromium or `--browser helium` for Helium.
   Reload the extension after installing the host.
3. Start and unlock the password-manager server.
4. Visit a login page and use the key button beside a credential field to
   choose an account. The extension can offer to save or update credentials
   when a login is submitted.

The service worker talks to `com.myproject.password_manager` through Chrome's
native-messaging API. Chrome launches the registered `pm-native-host` link,
which forwards a small, validated command set to the authenticated local
server. The extension no longer requests localhost access or stores the server
session token. If the `pm` executable moves, rerun the install command.

Autofill is form-aware: choosing an account fills only the username and current
password fields associated with that control. Other login forms and
new/confirmation-password fields on the page are left unchanged. Forms created
or revealed after page load are detected automatically.

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

The popup shows native-host/server/vault status and locks the vault; entry
management happens through the CLI and on-page controls.

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
- The local server requires a random session token (stored with 0600
  permissions) on every TCP and HTTP connection; vault, key and token files
  are created with 0600 permissions

Existing unversioned vaults remain readable. The next successful vault write
automatically stores them in the versioned format.
