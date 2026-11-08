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
- `src/cloud.rs` - Encrypted cloud transport, device credentials, and local sync checkpoints
- `src/server/cloud.rs` - Automatic sync and change notifications outside the vault owner queue
- `src/vault/sync.rs` - Authenticated application of downloaded snapshots on the vault owner
- `sync-server/` - Independent Go snapshot server, device enrollment, quotas, and Linux service unit
- `src/clipboard.rs` - Clipboard operations
- `src/file.rs` - Application paths, key-path validation, private permissions, and atomic file writes
- `src/protocol.rs` and `src/protocol/` - Versioned typed requests, responses, receipts, and shared browser command policies
- `src/lib.rs` - Shared production library used by the CLI and fuzz harness
- `docs/commands.html` - Browser-friendly CLI reference generated from Clap metadata
- `docs/commands.template.html` - Static layout used by the command-reference generator
- `extension/` - Browser extension (Chrome/Chromium)

See the [architecture review](architecture-review.md) for the reasoning behind
the domain, protocol, and session refactor.

For cloud-sync changes, run `go test -race ./...` and `go vet ./...` in
`sync-server/`. After building `pm`, run `python3 scripts/test_cloud_sync.py`
from the repository root to exercise two isolated clients against the actual Go
server. This test uses temporary profiles and loopback ports. See
[cloud sync](cloud-sync.md) for setup, protocol behavior, and current limitations.

The default `desktop` feature includes Iced 0.14 with its software renderer and
X11/Wayland support. A [local renderer patch](../vendor/iced_tiny_skia/README.pm.md)
fixes stale pixels along fractional scrollable edges. `cargo run --locked` opens
the GUI; append a command after `--` to use the CLI. `--no-default-features` builds
the CLI/server without GUI dependencies, including for the fuzz package. CLI
parsing, native messaging, dynamic completions, and clipboard helpers run without
initializing Iced.

The [font database bridge](../vendor/fontdb-compat/README.md) uses maintained
fontdb 0.24 behind Cosmic Text's compatible 0.23 API. The
[window integration patch](../vendor/iced_winit/README.pm.md) selects Crossfont
for decorated Wayland titlebars, removing the unmaintained ttf-parser dependency.
Linux desktop builds require pkg-config and Fontconfig/FreeType development
packages (`sudo apt-get install pkg-config libfontconfig1-dev libfreetype6-dev`
on Debian/Ubuntu). CLI-only builds exclude these desktop dependencies.

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

For short edit/test cycles, run the affected boundary first:

```bash
cargo test --locked --no-default-features --lib vault::test::normalized_search
cargo test --locked --bin pm gui::presentation::tests
node --test extension/background_native.test.js
```

Use a test-name prefix to select related cases. The direct Node command is a
fast unit-only iteration; `npm run test:extension:coverage` also checks generated
bundles and coverage gates. Run `npm run validate` once the changes are stable,
plus the browser/cloud/native checks appropriate to the change.

### CI suite selection and merged PRs

CI runs on pull requests and pushes to `main`; feature-branch pushes do not
start a second run. A planner selects whole suites from the complete Git diff,
including deletions and both sides of renames:

- Ordinary Markdown documentation skips application tests. Generated command
  references still run Rust validation.
- GUI/assets changes run Rust tests, coverage, and platform checks.
- Shared Rust, integration-test, and vendor changes also run browser, cloud,
  and fuzz integration checks.
- Extension changes run extension validation and browser integration. Generated
  command-contract changes also run Rust consistency checks.
- Go server changes run cloud validation and the two-device integration test.
- Dependency manifests/lockfiles run the affected suites and dependency audits.
  Root Cargo changes select all suites.
- Workflow/planner changes and unknown inputs select all suites. A missing Git
  diff also falls back to all suites.

`npm run validate` still runs the complete local validation. CI splits it into
`npm run validate -- rust` on each platform and
`npm run validate -- extension` once on Linux. Browser integration builds the
CLI/native host with `--no-default-features`, without the desktop renderer.

A successful PR workflow uploads the exact checked-out Git tree as a small
artifact. A push to `main` reuses that result only for a merged PR from this
repository, in the same workflow, with a successful run, an identical tree, and proof that all suites needed
for the main-branch diff actually passed.
This works across merge and squash commits even though their commit IDs differ.
Each workflow verifies its own result independently. Missing/expired artifacts,
API errors, direct pushes, changed merge results, and unfinished/failed PR runs
run the selected checks normally. Proof artifacts expire after 14 days.

The lightweight planner and final result jobs still run after merging; expensive
suites are skipped when reuse is verified. The planner's job summary links the
reused PR run or lists the selected suites. `CI result`, `Security result`, and
`Fuzz result` reject failures, cancellations, and unexpectedly skipped selected
jobs; these are the stable checks to require if branch protection is enabled.
Branch protection itself does not deduplicate tests. Earlier main-branch runs
are allowed to finish so later pushes cannot cancel validation of direct pushes.

Weekly full runs bypass selection and reuse to catch selection gaps and refresh
shared caches on `main`. Manual workflow dispatch also runs all suites. PRs
restore these shared Rust caches without saving PR-specific copies.

The dev/test profiles optimize Argon2, Blake2, and zxcvbn while leaving application
debug information intact. This adds a one-time dependency compilation cost but
avoids repeatedly running cryptographic and strength-estimation loops without
optimization. Production KDF parameters and release optimization are unchanged.
Browser tests use two file-level workers with separate profiles and vaults;
use `npm run test:e2e -- --workers=1` to diagnose an ordering/resource issue.

The desktop build also enables the local AccessKit bridge in
[`iced_winit`](../vendor/iced_winit/README.pm.md), with semantic widget metadata
from the local core/widget patches. Protected inputs omit their contents from
the accessibility tree. The Unix adapter uses the AT-SPI `IsEnabled` property
for compatibility with AT-SPI 2.62.1. This integration needs native validation;
compilation and a semantic tree do not demonstrate complete Orca usability.

The Linux protocol helpers are local zbus 6 ports so the desktop does not bring
back the abandoned standalone zvariant/zbus_names implementations. Their
READMEs describe the changes and upstream versions. The protocol and XML helper
crates are workspace members for their upstream tests; the application remains
the default workspace member. `npm run validate` runs those tests on Linux along
with the Unix adapter's wire-signature and serialization checks. Registry audits
do not cover path sources, so local ports still need source review and native
validation when updated. The actual DBus codec/transport and XML parser remain
maintained registry dependencies checked by the dependency audit.

On Linux with Orca, GTK3, PyGObject, AT-SPI, and DBus installed, run
`python scripts/test_gui_accessibility.py` after building. The smoke check uses
private profiles and buses, a GTK reference control, and the real desktop app.
It checks named controls, a button action, protected input focus, and, on Hyprland
with `wtype`, typing and Tab navigation. `--output DIR` retains diagnostic
evidence; `--orca-runtime DIR` accepts an extracted user-local Orca installation.
For repeatable native X11 checks without desktop focus changes, supply
`--xvfb /path/to/Xvfb`; this also needs `xdotool`. The extended check requires
Orca to announce the protected field and saved-settings feedback, exercises
dropdown selection, and checks that keyboard focus scrolls into view at 480px.
It also attempts multiline note input, line navigation, caret movement, and text
selection in a temporary synthetic vault. Inspect `result.json` for the completed
checks and failure phase; a partial run does not certify native accessibility.
Use `--scale 130` to repeat the checks with enlarged controls. On X11, the
check also clicks a control at its exported accessible bounds to verify that
physical pointer coordinates agree with accessibility coordinates.
The script never examines personal vaults or other applications' control trees.
Full spoken-output quality, editing, scrolling, menus, and IME checks remain part
of the native acceptance review.

The GUI tests also exercise the real Iced software renderer without opening a
window or reading personal vaults. To export the synthetic fixtures as PPM images:

```bash
PM_GUI_REVIEW_DIR=/absolute/path/to/renders cargo test --locked --bin pm gui::render_tests
```

These checks cover minimum windows, enlargement, themes, long content, recovery
banners, and bounded large-vault lists. They verify widget layout and rendering;
they do not verify native window events, IME, file dialogs, or screen-reader support.

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
Rust dependency audits deny warnings as well as vulnerabilities, including
unmaintained and yanked packages.
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
a receipt. Expected item revisions reject stale edits. Receipts distinguish
pending, committed, failed, unknown, and committed-but-durability-uncertain states.
Locking discards cached secret responses while retaining nonsecret receipts.
Receipts are not durable across daemon restarts or unlimited retention. An unknown
outcome requires state inspection and explicit acknowledgement in the desktop client or extension popup;
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

The content entrypoint uses explicit modules. A per-document/root
controller captures credentials from supported nested open shadow roots and
cleans up its observers and listeners. Closed shadow roots are not supported.
After editing frontend modules, regenerate the checked-in bundles:

```bash
npm run build:extension
```

The dependency-free build writes `content_runtime.js`;
unit tests, browser tests and shared validation check that they are current.
Browser operation policies, runtime validators and TypeScript declarations come
from `src/protocol/native_contract.rs` and its template. Regenerate them with:

```bash
cargo run -- generate-command-contract
cargo run -- generate-command-contract --check
```

See [Testing](#testing) for prerequisites and CI checks.

## Simplified boundaries

The desktop is the full vault editor; the browser extension handles site-scoped
selection, autofill, credential-save decisions, signup generation, Duo prompts,
status, locking, and operation review. The full browser manager and its native
editing API are removed. Popup acknowledgement requires a server review reporting
an unknown operation plus explicit inspection; it never replays the original write. Recovery identities for
retired editor operations remain reviewable after an extension upgrade.

CLI `view` and `search` and desktop search translate into one `List(SearchFilter)`
RPC. Protocol version 3 rejects older contracts. Stop the daemon with the previous
build before replacing it, then update the native host (`pm native-host update`),
reload the extension, and start the new daemon. An older daemon cannot accept a
version-3 stop command. The durable vault schema is unchanged.

Session lifecycle commands run before unlocked dispatch. Other commands borrow a
complete vault and its cached credentials through `with_unlocked`; ordinary errors
retain the same session epoch, while a panic leaves the session locked. Desktop
request activity is one `RequestState`; edit/view refreshes share an `ItemIntent`.
The persistence encoder uses a reference map and vector with the existing schema.

Sync server deployment is an independent administration task. The Rust binary no
longer embeds Go source, installer scripts, SSH state, or remote-update logic.
