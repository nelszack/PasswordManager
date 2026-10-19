# Security policy

This project is a local password manager. Passing tests and using established
cryptography do not constitute an independent security audit.

## Reporting a vulnerability

Report security weaknesses privately through
[GitHub's vulnerability reporting page](https://github.com/nelszack/PasswordManager/security/advisories/new)
when private reporting is available. If GitHub does not offer private reporting,
open an issue requesting a private reporting channel without publishing exploit
details. Do not put passwords, vault files, key files, session tokens, OTP
secrets, Duo activation links or signing keys, or unredacted browser traces in
an issue or report.

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
history, deleted items, TOTP/HOTP secrets and counters, Duo device signing keys,
and the authenticated local session token.

The trusted components are the local operating system and user account, the
`pm` executable, its dependencies, and the installed browser extension and native
host. Websites, page scripts, imported documents, encrypted file headers, native
messages, and network responses are untrusted inputs.

Vaults and backups authenticate their ciphertext and format metadata. Password
keys use Argon2id; external key files must be kept separately from application
data. File permissions restrict vault and token access to the current user.
Vault and backup writes enforce a 128 MiB encrypted-file limit before replacement.
Export and backup destinations cannot replace files in application data or
configuration directories, including through symlink aliases. An exclusive
operating-system file lock prevents servers on different ports from sharing one
data directory and rotating each other's session tokens or writing competing
vault states.
Backup restoration enforces the same limit on the actual file read; external
key files must be regular files within a 1 MiB limit.
The loopback server uses a rotating token and authenticated encrypted transport.
Requests and responses use a versioned, named-field contract, and every response
requires its connection's authenticated encryption key. The single vault worker
owns either locked state or a complete unlocked session with cached key material.
Private passwords, notes, custom-field values, seeds and signing keys own their
cleanup on drop; invalid requests and early returns follow the same lifetime rules.
A shared 64 MiB budget bounds ciphertext and plaintext request buffers before
authentication; requests exceeding the available budget are rejected.
The extension derives site identity from browser sender metadata and requires
site-scoped selection rather than trusting a domain supplied by page scripts.
Vault-management requests are separately restricted to the extension's manager
page using the browser-provided extension ID and page URL. List responses contain
summaries only; explicit reveal requests fetch one selected item. OTP seeds and
Duo signing keys are never returned by vault-management reads. Management copying uses the server's
clipboard worker and existing lock cleanup.
Native OTP responses carry structured code, lifetime and counter data rather
than parsed terminal output. Secret and custom-field data responses preserve
the stored bytes, including whitespace and empty values.
Pending navigation records are consumed once and removed on expiration or tab
closure; periodic cleanup removes expired session records after worker restarts.
Site matching parses HTTP(S) URLs and compares scheme, normalized hostname,
and effective port; bare domains default to HTTPS. Ambiguous URLs fail closed.
Save prompts request summaries and never delay or replay form submissions based
on a password match. Unchanged logins explicitly selected through the secure
picker suppress save prompts using a short-lived fingerprint scoped to the
originating tab, frame, and origin. This comparison never fetches unselected
vault secrets; locking or disconnecting clears the fingerprints.
New Unix key files are private at creation; Windows key
writers deny shared data access until the private ACL is installed and the
writer closes. Terminal presentation escapes controls in imported metadata.

Duo enrollment and Push requests restrict hosts to HTTPS Duo endpoints, validate
certificates, disable redirects, and bound response sizes and network timeouts.
Push uses RSA-SHA512 signatures through AWS-LC. Device credentials stay inside
the encrypted vault; network waits carry signed requests without the private key.
Review tokens use an ephemeral MAC key that is omitted from serialization and
cleared on lock. Decisions re-fetch and validate the exact request and unlock
session before signing. The CLI requires interactive confirmation (an a/d choice
after review in interactive watch). Extension decision buttons require trusted
clicks and confirmation. The automatic Duo window uses browser-derived login
origins and matching login summaries, or a recent same-tab login for Duo-hosted
redirects. Duo-hosted challenges can also match the exact HTTPS api- issuer to
stored device enrollments, without exposing device credentials or allowing a
different Duo server to match. Its tokens and request data are never returned to
content scripts.
A trusted Approve/Deny click confirms the displayed request without another
dialog. Decisions bind to the reviewed request, active originating document,
and unlock session; navigation, dismissal and lock invalidate the window.
Verified Push requires
the code shown on the login page; codes from the Push payload are never supplied.
Unknown Push modes and unsupported device requirements block approval.
Duo network waits run outside the vault owner, and the extension routes lock/status
separately from Push requests. Enrollment commits require the original unlock
session and unchanged target item.

### What these controls protect

Dynamic shell completion runs before asynchronous runtime and application
initialization. Completion queries use CLI metadata and filesystem path hints,
without reading vault contents or configuration, unlocking a vault, or sending
commands to the server. Native-host invocations bypass completion activation.

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

System-event locking uses the same session and clipboard cleanup path. OS
notification availability varies by platform and desktop; unavailable sources
are reported in status. Linux standalone-locker detection checks same-user
executables at 250 ms intervals. These notifications and checks supplement the
inactivity timer and cannot guarantee delivery before a forced suspend or process
termination. Resume notifications also request locking.

Vault mutations stage complete affected items and use atomic file replacement.
A pre-replacement failure discards the staged change. A directory-sync failure
after replacement retains the committed
memory state and reports uncertain durability; the operation must not be blindly
retried. Rekeying replaces ciphertext at the same opaque vault filename. After an
interruption there is one vault file, holding either the old or new ciphertext.
If power fails before directory sync completes, which version survives depends
on the filesystem. Keep both credentials until the rekey succeeds durably, or
verify which credential opens the file after an interrupted operation.

Mutation IDs provide bounded duplicate suppression within the current daemon,
and expected item revisions prevent stale manager edits. The daemon retains at
most 256 operation results and does not persist these receipts across restarts.
Unknown outcomes require explicit state inspection before the manager permits
another change; pending operations cannot be dismissed as unknown. Reconnection
and acknowledgement never replay the original write. Operation IDs do not
provide exactly-once guarantees for external Duo actions or clipboard effects.

### Limits

- Malware running as the same user, administrators, debuggers, or a compromised
  operating system can access unlocked secrets or the local session token.
- `pm get` redacts secret custom fields by default. `--reveal-secrets` displays
  them, `--field NAME` prints a selected custom-field value, and `--password-only`
  prints the primary secret. `--field NAME --copy` copies without printing the
  value. `--json` returns the selected structured data without additional redaction. Terminal
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
  and handle them separately from encrypted backups. Portable JSON and encrypted
  backups include Duo Push credentials; CSV omits OTP and Duo credentials.
- A restored Duo enrollment uses the same device identity. Push decisions do not
  advance the local HOTP counter, but HOTP generation on separate vault copies
  has independent counters that are not synchronized.
- Duo mobile endpoints are undocumented and may change or reject this client.
  This client cannot provide mobile hardware attestation. Locking cannot recall
  an already-sent decision; a failed decision response can have an unknown outcome.
  Enrollment can consume an activation link even if the result cannot be saved.
- Encrypted-header resource limits bound individual KDF requests, but availability
  under hostile local files or authenticated clients is not guaranteed.

## Security regression testing

Run the Rust and extension suites, strict linting, and browser end-to-end tests as
described in the [contributor guide](docs/development.md#testing). Persistence tests inject failures before replacement and
after replacement to check key adoption, rollback, and restart behavior. Subprocess
tests also exit abruptly at both stages of rekeying and reopen the surviving vault. Clipboard
tests check replacement, deadlines, lock cleanup, and transient failures.

The [fuzzing guide](fuzz/README.md) describes coverage-guided targets for encrypted
headers, native messages, and import parsers. Use synthetic data exclusively;
fuzz corpora, crash artifacts, and browser traces may preserve their inputs.
