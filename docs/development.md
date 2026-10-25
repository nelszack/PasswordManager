# Contributor guide

[Back to README](../README.md) · [User guide](user-guide.md) · [Architecture review](architecture-review.md)

- [Architecture](#architecture)
- [Testing and coverage](#testing)
- [Releases](#releases)
- [Development and generated artifacts](#development)

## Architecture

- `src/main.rs` and `src/app/` - CLI initialization, explicit output settings, local commands, and conversion to server requests
- `src/gui/` - Iced desktop client, asynchronous server adapter, editor state, and native widgets
- `src/gui/settings.rs` - Complete configuration form, input validation, and edits relative to its loaded settings
- `src/desktop.rs` - Linux application-menu launcher installation for the same executable
- `src/server.rs` and `src/server/` - Authenticated connections, a bounded vault worker, command handling, and external effects
- `src/client.rs` and `src/client/transport.rs` - Authenticated Result-returning client with explicit connection settings
- `src/client/presentation.rs` - Human-readable rendering of typed response records
- `src/native_messaging.rs` - Chrome native host protocol and registration
- `src/vault.rs` and `src/vault/` - Complete item aggregates, staged mutations, import/export, and versioned document storage
- `src/secret.rs` - Redacted secret fields that wipe their contents on drop
- `src/encryption.rs` - Encryption/decryption utilities
- `src/password.rs` - Password generation and strength checking
- `src/cli.rs` - CLI argument parsing
- `src/config.rs` - Configuration management
- `src/clipboard.rs` - Clipboard operations
- `src/file.rs` - Application paths, key-path validation, private permissions, and atomic file writes
- `src/protocol.rs` and `src/protocol/` - Versioned typed requests, responses, receipts, and shared browser command policies
- `src/lib.rs` - Shared production library used by the CLI and fuzz harness
- `docs/commands.html` - Browser-friendly CLI reference generated from Clap metadata
- `docs/commands.template.html` - Static layout used by the command-reference generator
- `extension/` - Browser extension (Chrome/Chromium)

See the [architecture review](architecture-review.md) for the reasoning behind
the domain, protocol, and session refactor.

The default `desktop` feature includes Iced 0.14 with its software renderer and
X11/Wayland support. A [local renderer patch](../vendor/iced_tiny_skia/README.pm.md)
fixes stale pixels along fractional scrollable edges. `cargo run --locked` opens
the GUI; append a command after `--` to use the CLI. `--no-default-features` builds
the CLI/server without GUI dependencies, including for the fuzz package. CLI
parsing, native messaging, dynamic completions, and clipboard helpers run without
initializing Iced.
The Tokio CLI runtime is created only for CLI dispatch, leaving Iced's event
loop on the main thread. Windows keeps the console subsystem for CLI and native
messaging I/O; GUI dispatch releases an automatically created console only when
no other process shares it, preserving existing command prompts.

The desktop GUI calls `AuthenticatedClient` from blocking workers dispatched
through Iced tasks. It never owns a second decrypted vault. Status polling does
not extend inactivity; session changes clear selections and editor state. Reads,
copies, and edits bind to the selected unlock session, and item writes include
the reviewed revision. Late responses from before an explicit lock are ignored.
Mutation IDs are recorded privately under `desktop-operations/` before sending;
uncertain outcomes block further mutations until reviewed, including after GUI
restart. Journal records contain only port numbers and random operation IDs.

The GUI workflows module prepares typed requests, confirmation snapshots, and
reports for recovery, file operations, authenticators, search, and browser
integration. Offline discovery and read-only settings refresh are independent of
server status. Three-way settings refresh preserves dirty form fields; operations
that use clipboard/default generation policy reread configuration before dispatch.
Temporary connection changes invalidate prior replies and keep per-port journals
on disk. Confirmation snapshots retain the reviewed command, session, and
item revision; input edits cancel them and dropped snapshots wipe command
secrets. TOTP/Duo refresh yields to status polling and never extends unlock.
TOTP stops on focus loss; passive Duo request polling continues while switching
to the browser or other tabs, using a captured item/session/revision target. TOTP
watch copies only newly observed codes through a tracked clipboard mutation; these
completions must not be canceled as passive reads. Locking or endpoint changes stop
both watches. An unexpired Duo request pauses automatic polling so the reviewed
snapshot and decision controls cannot disappear on a later empty response. Explicit
fetch, successful response, or expiry releases that pause; server status polling
continues and decisions still revalidate the request remotely. Duo requests have
their own item-scoped result cache beside the fetch and decision controls;
OTP results and other reports do not overwrite it. A separate reveal epoch
suppresses late secret replies without discarding mutation receipts (including
HOTP counter updates). Hidden field drafts preserve redacted values unless
explicitly replaced.

For desktop changes, run `cargo test --locked --bin pm` and the CLI integration
tests in addition to shared validation. Manually check create/unlock, list/search,
editing, timed reveal, copy cleanup, external locking, and GUI close/reopen while
the server remains up. Native widget state, keyboard/IME behavior, accessibility,
and compositor integration require platform testing; browser tests do not exercise
the Iced window.

The key-file chooser uses `rfd`. It creates the parented picker on Iced's window
thread so AppKit calls stay on the main thread, then awaits the result in a task.
Windows uses its native file dialog; macOS uses an AppKit sheet. Linux needs
`libdbus-1.so.3`, `xdg-desktop-portal`, and a portal backend providing FileChooser
(such as the GTK or KDE backend); a Wayland-only backend may need one of these
alongside it. The path can also be entered manually. The CLI-only build excludes
the dialog dependency. Selection fills the unlock path without reading the key
or unlocking automatically.

CI validates the default desktop build on Linux, Windows, and macOS, checks a
CLI-only build on each platform, and checks both Intel and Apple Silicon macOS
targets. Feature branch pushes run these checks before merging. Native visual
and file-dialog smoke tests still need a desktop session on each OS.

Vault IDs identify files; credentials authenticate the selected vault. When there
is one vault, `pm unlock` selects it. With multiple vaults, use `--vault-file ID`
or set `pm config --default-vault ID`. Independent vaults can share a credential.
The internal protocol and vault document formats changed during development;
older binaries and vault files need a verified portable export/import using the
original binary. Upgrade the CLI, native host and extension together. Future
runtime compatibility uses protocol versions rather than matching package versions.

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

The shared validation command used by both CI and release packaging runs the
checks above, verifies the generated command reference, and checks every
extension script's syntax. The command-reference check reuses the all-features
executable built for the Rust integration tests:

```bash
npm ci
npm run validate
```

The extension coverage and shared validation commands require Node.js 26.7 or
newer. CI and release validation use Node 26; browser end-to-end tests use Node 22.
Extension unit coverage enforces individual thresholds for the background
services, including native request and pending-credential lifecycles.

Browser tests run headlessly by default, so they do not open desktop windows or
take focus and do not require a graphical session. The
real native-host/server integration test runs on Linux and requires the binary
at `target/debug/pm`; it is skipped if the binary is missing. Set up and run on
Linux with:

```bash
cargo build --locked
npx playwright install --with-deps chromium
npm run test:e2e:coverage
# To watch the browser while debugging (requires a graphical session):
PM_E2E_HEADED=1 npm run test:e2e
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
Rust build caches are saved on `main` and restored by pull requests, reducing
duplicate cache storage without skipping checks. Default-feature builds remain
covered by the browser integration and release jobs.

Protocol tests check explicit operation tags, named fields, version rejection,
request correlation, and exact secret payloads. The native host receives typed
records, OTP codes, counters, and lifetimes independently of CLI wording. Remote
`--json` results expose records in `data`; config, vault listings and TOTP watch
also expose structured data.

Dependency changes are scanned against the RustSec advisory database and
reviewed on pull requests. Dependabot checks Rust crates and GitHub Actions
weekly, including npm browser-test dependencies and the fuzz harness. Scheduled
security checks audit the Rust and npm lockfiles, including the fuzz lockfile.
Repository secret-scanning and push-protection settings are managed separately
from the checked-in workflows.

Coverage-guided fuzz targets and scheduled CI sessions exercise encrypted headers,
native messages, and import parsers. See [fuzz/README.md](../fuzz/README.md) for local
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
the browser manifest's `version_name` for release packaging. Runtime compatibility
uses the protocol version. The manifest's numeric `version` remains an independent extension-package
revision because browser stores require monotonically increasing revisions.

Then open the **Release** workflow in GitHub Actions, choose **Run workflow**,
and enter that existing tag. The pipeline runs the shared validation command,
including extension version synchronization and coverage, then
creates a **draft** release with archives for Linux x86-64, Windows x86-64,
macOS Apple Silicon, and macOS Intel. Review the draft and publish it manually
from GitHub's Releases page.

Each archive contains `pm`, the browser extension, README, security policy, command
reference, fuzzing guide, and shell completions. Draft releases include generated notes, SHA-256 checksums, and
GitHub build-provenance attestations. Prerelease tags such as
`v0.2.0-beta.1` are marked as prereleases, but still remain drafts until you
publish them.

## Development

Vault logic lives in `src/vault/`, grouped by entries, queries, recovery, OTP, Duo,
imports, exports, backups, and persistence. Each complete item owns its metadata,
secret history, authenticators, Duo enrollment, revision, and active/trash state.
The encrypted `VaultDocument` has its own schema version and vault identity;
paths, keys and runtime review tokens are excluded from it.

Mutations stage affected complete items and serialize a combined document view.
Live state changes only when atomic file replacement commits. A failure before
replacement discards the staged data; a directory-sync failure afterward adopts
committed state and keys and reports uncertain durability. Imports stage a bulk
change. Secret fields wipe on drop, including validation and early-return paths.
Memory-only mutation tests use an explicit memory store; missing credentials
cannot silently turn a persistent write into a memory-only success.

The daemon's bounded worker owns `VaultSession::Locked` or a complete unlocked
vault with cached encryption material. It prioritizes lock/shutdown control work,
uses one inactivity deadline, and publishes nonsecret status independently of
long operations. A filesystem commit already in progress must finish at its safe
boundary before locking. Duo and breach network waits run outside the owner;
Duo finalization rechecks the unlock session and item revision. Connections carry
an explicit response encryption key, with no plaintext-response fallback.

The protocol uses versioned envelopes, explicit operation tags and named fields.
Domain reads return records; `src/client/presentation.rs` formats human output,
and the native host only adapts browser framing and validated operations. CLI
output settings are explicit values in the executable; reusable clients return
results instead of terminating the process.

Mutation IDs deduplicate requests within a running daemon, with up to 256 retained
results and a 64 KiB limit on each cached result. Large reads/reports retain only
a receipt. Expected item revisions reject stale manager edits. Receipts distinguish
pending, committed, failed, unknown, and committed-but-durability-uncertain states.
Locking discards cached secret responses while retaining nonsecret receipts.
Receipts are not durable across daemon restarts or unlimited retention. An unknown
outcome requires state inspection and explicit acknowledgement in the manager;
a pending operation cannot be acknowledged. Neither reconnect nor acknowledgement
replays an uncertain write. Remote Duo effects can remain uncertain even when the
local vault is healthy.

The extension keeps dependency-injected background services for native requests,
status, navigation context, pickers, prompts and message routing. Only trusted
extension decisions authorize saves and selected-secret release. Nonsecret
username navigation context and unresolved operation IDs/actions use session
storage; secret decision windows are invalidated on worker restart. Idle status
uses a one-minute alarm, with two-second polling while extension UI is open.
Native lanes close when idle and reconnect after a bounded silent-port deadline.

Content and manager entrypoints use explicit modules. A per-document/root
controller captures credentials from supported nested open shadow roots and
cleans up its observers and listeners. Closed shadow roots are not supported.
After editing frontend modules, regenerate the checked-in bundles:

```bash
npm run build:extension
```

The dependency-free build writes `content_runtime.js` and `manager_runtime.js`;
unit tests, browser tests and shared validation check that they are current.
Browser operation policies, runtime validators and TypeScript declarations come
from `src/protocol/native_contract.rs` and its template. Regenerate them with:

```bash
cargo run -- generate-command-contract
cargo run -- generate-command-contract --check
```

See [Testing](#testing) for prerequisites and CI checks.
