# Password Manager

A secure, local-first password manager with a CLI interface and browser extension.

## Features

- **Secure Storage**: Encrypted vault using Argon2 and ChaCha20-Poly1305
- **Password Generator**: Generate strong passwords with customizable length
- **Password Strength Checker**: Evaluate password strength with zxcvbn
- **Browser Extension**: Auto-fill passwords from the extension popup
- **Clipboard Integration**: Secure clipboard with auto-clear timeout
- **Import/Export**: Support for CSV and JSON formats
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
`~/.local/share/password_manager/session.key`). The CLI client authenticates
automatically; the browser extension needs this token (see below).

### Generate a Password

```bash
pm genpass --length 20 --copy
```

### Add a New Entry

```bash
pm add --name "github.com" --username "user@email.com" --generate-password --copy
```

### View All Entries

```bash
pm view
```

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

### Lock/Unlock

```bash
pm lock
pm unlock
```

### Import/Export

```bash
pm import --path backup.csv --new
pm export --path backup.csv
```

### Check Password Strength

```bash
pm passcheck --password "mypassword123"
```

### Configure Settings

```bash
pm config --length 24 --stats --clipboard-timeout 30
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

1. Load the `extension` folder as an unpacked extension in Chrome
2. The extension connects to `http://127.0.0.1:7878`
3. Click the extension icon, paste the session token from the file printed by
   `pm start` into the "Session token" field, and click **Save Token**
4. Use the extension icon to view and manage passwords

## Architecture

- `src/main.rs` - CLI entry point and command routing
- `src/server.rs` - Background server for extension communication
- `src/client.rs` - Client for server communication
- `src/vault.rs` - Vault management and storage
- `src/encryption.rs` - Encryption/decryption utilities
- `src/password.rs` - Password generation and strength checking
- `src/cli.rs` - CLI argument parsing
- `src/config.rs` - Configuration management
- `src/clipboard.rs` - Clipboard operations
- `src/file.rs` - File import/export
- `extension/` - Browser extension (Chrome/Chromium)

## Security

- Master password derived using Argon2 with a random per-vault salt
- Entries encrypted with ChaCha20-Poly1305
- Keys derived with BLAKE3
- Zeroize for secure memory cleanup
- Configurable auto-lock timeout
- The local server requires a random session token (stored with 0600
  permissions) on every TCP and HTTP connection; vault, key and token files
  are created with 0600 permissions
