# Security policy

This project is a local password manager. Passing tests and using established
cryptography do not constitute an independent security audit.

## Reporting a vulnerability

Report security weaknesses privately through
[GitHub's vulnerability reporting page](https://github.com/nelszack/PasswordManager/security/advisories/new)
when private reporting is available. If GitHub does not offer private reporting,
open an issue requesting a private reporting channel without publishing exploit
details. Do not put passwords, vault files, key files, session tokens, TOTP
secrets, or unredacted browser traces in an issue or report.

Include the affected version and platform, the relevant trust boundary, expected
and observed behavior, and a minimal reproduction using synthetic credentials.
For persistence problems, identify whether the operation failed before or after
file replacement. Coordinate disclosure with the maintainer while a fix and
regression test are prepared. No response-time guarantee is currently offered.

Use the newest available release. Older versions do not have a separately
maintained security-fix branch.

## Threat model

### Assets and boundaries

The assets are master passwords, external keys, decrypted entries, password
history, deleted items, TOTP secrets, and the authenticated local session token.

The trusted components are the local operating system and user account, the
`pm` executable, its dependencies, and the installed browser extension and native
host. Websites, page scripts, imported documents, encrypted file headers, native
messages, and network responses are untrusted inputs.

Vaults and backups authenticate their ciphertext and format metadata. Password
keys use Argon2id; external key files must be kept separately from application
data. File permissions restrict vault and token access to the current user.
Vault and backup writes enforce a 128 MiB encrypted-file limit before replacement.
Backup restoration enforces the same limit on the actual file read; external
key files must be regular files within a 1 MiB limit.
The loopback server uses a rotating token and authenticated encrypted transport.
A shared 64 MiB budget bounds ciphertext and plaintext request buffers before
authentication; requests exceeding the available budget are rejected.
The extension derives site identity from browser sender metadata and requires
site-scoped selection rather than trusting a domain supplied by page scripts.
Site matching parses HTTP(S) URLs and compares scheme, normalized hostname,
and effective port; bare domains default to HTTPS. Ambiguous URLs fail closed.
Save prompts request summaries and never delay or replay form submissions based
on a password match. New Unix key files are private at creation; Windows key
writers deny shared data access until the private ACL is installed and the
writer closes. Terminal presentation escapes controls in imported metadata.

### What these controls protect

Copying a locked encrypted vault without its password or external key does not
provide plaintext access. Ciphertext or authenticated-header modification causes
an authentication failure. This does not distinguish a wrong password from
modified ciphertext and does not prevent deletion or replacement of the file.

Explicit locking and inactivity locking remove server-held vault secrets and
cached encryption keys. Locking also requests immediate cleanup of the latest
server-owned clipboard secret, only if the clipboard still contains that value.
The clipboard worker retains its copy while retrying transient cleanup failures;
that buffer can outlive the locked vault when the clipboard is unavailable.
A manual cleanup failure is reported even though the vault itself has already
locked. Background cleanup failures appear in server status and the extension badge.

Vault mutations use an atomic file replacement. A pre-replacement failure rolls
back memory. A directory-sync failure after replacement retains the committed
memory state and reports uncertain durability; the operation must not be blindly
retried. Rekeying replaces ciphertext at the same opaque vault filename. After an
interruption there is one vault file, holding either the old or new ciphertext.
If power fails before directory sync completes, which version survives depends
on the filesystem. Keep both credentials until the rekey succeeds durably, or
verify which credential opens the file after an interrupted operation.

### Limits

- Malware running as the same user, administrators, debuggers, or a compromised
  operating system can access unlocked secrets or the local session token.
- `pm get` redacts secret custom fields by default. `--reveal-secrets` displays
  them, `--field NAME` prints a selected custom-field value, and `--password-only`
  prints the primary secret. `--field NAME --copy` copies without printing the
  value. `--json` wraps the same output without additional redaction. Terminal
  logs can retain explicitly revealed values.
- Autofill necessarily gives the selected secret to the destination page. A
  compromised website or browser can read it after delivery.
- Zeroization reduces the lifetime of application-owned buffers; it cannot
  guarantee removal from swap, crash dumps, OS buffers, allocators, or copies made
  by other software. Browser JavaScript has no reliable memory-zeroization API.
- Clipboard history managers and other applications can retain copied secrets.
  Auto-clear cannot retract those copies. CLI-generated copies have a separate
  detached owner and timeout; locking the server does not cancel these helpers.
  Process termination or an unavailable clipboard can prevent cleanup.
- Old backups, filesystem snapshots, and historical copies remain decryptable
  with their original credentials after rekeying. Rekeying does not securely
  erase storage blocks or detect rollback to an older authenticated vault.
- CSV and portable JSON exports contain plaintext secrets. Protect their storage
  and handle them separately from encrypted backups.
- Encrypted-header resource limits bound individual KDF requests, but availability
  under hostile local files or authenticated clients is not guaranteed.

## Security regression testing

Run the Rust and extension suites, strict linting, and browser end-to-end tests as
described in the README. Persistence tests inject failures before replacement and
after replacement to check key adoption, rollback, and restart behavior. Subprocess
tests also exit abruptly at both stages of rekeying and reopen the surviving vault. Clipboard
tests check replacement, deadlines, lock cleanup, and transient failures.

The [fuzzing guide](fuzz/README.md) describes coverage-guided targets for encrypted
headers, native messages, and import parsers. Use synthetic data exclusively;
fuzz corpora, crash artifacts, and browser traces may preserve their inputs.
