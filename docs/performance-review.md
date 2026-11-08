# Performance, compilation, and test review

Reviewed 2026-11-07 against the working checkout on `main`, then implemented locally at the user's request. Existing edits in four test files were preserved. The review findings below describe the original checkout; implementation status and measurements are tracked separately here.

The later architecture simplification supersedes parts of this performance pass:
SSH provisioning and the full browser manager have been removed; the custom
streamed serializer was reverted to the simpler reference-map/vector encoder.
The remaining runtime optimizations and dependency profiles are retained. See
[the current architecture](development.md#simplified-boundaries). The retired,
previously modified browser-manager test was archived before deletion in
`/tmp/pm-retired-browser-manager.tar.gz`; the pre-simplification working diff is
`/tmp/pm-before-simplification.patch`. These archives are temporary local files.

## Architecture simplification verification

The subsequent simplification passed the sequential queue recorded at
`/tmp/check-queue-qbb4qkqq/result.json`:

- Shared validation: formatting, generated docs/contracts/bundle checks, 184 extension unit tests with coverage gates, all vendor suites, 223 library tests, 170 desktop/binary tests, 31 CLI integration tests, two protocol tests, and Clippy with warnings denied.
- CLI-only compilation, CLI-only build, and default desktop build.
- All 34 retained browser tests with coverage, including the real native-host credential-save flow; no skips. Browser content runtime byte coverage was 84.72%, with 81.34% aggregate browser byte coverage.
- Go race tests and vet, plus real two-device download/unlock, automatic sync, conflicting-edit preservation, comparison copies, credential-replacement failure recovery, and restart durability.
- An isolated legacy-config check confirmed that an old `ssh_target` field is ignored while the sync URL and automatic-sync choice are preserved.
- `git diff --check` passed. Native accessibility, macOS/Windows execution, fuzzing, and Rust LLVM coverage were not rerun for this pass.

The source is ready for review. Stop an older daemon with its previous build
before deploying protocol 3, update the native host, reload the extension, then
start the new daemon. Vault ciphertext and document schemas are unchanged.

## Implementation at the performance-review stage

- Automatic sync compares session/revision, file metadata, binding, and endpoint before taking a full snapshot. Notifications and a 30-second fallback still force content checks. Snapshot buffers transfer ownership without a full copy.
- HTTP transports share connection pools without retaining credentials in default headers; each new cloud client still rereads and validates its device token.
- The Go server releases its global mutex while uploads/downloads stream. Uploads reserve payload and metadata quota, recheck the base version before committing, and release reservations and staging files on failure. Commits remain serialized. Tests cover blocked transfers, pruning during a download, competing writers, quota exhaustion, and interrupted uploads.
- Duplicate imports retain a next-suffix cursor for each name/username namespace. Tests cover gaps, repeated duplicates, preview agreement, and independent usernames.
- Server search normalizes each filter once. Desktop search caches matching indices until the query, kind, or list changes; refresh/lock clears the cache. Cached query text is zeroized when discarded.
- Password strength scores are cached per item, discarded on mutable access, omitted from persistence/equality, and dropped with the session. Tests cover commit/rollback and reload.
- Persistence streams an ordered live/staged merge, preserving the existing schema and encoded byte shape. It no longer builds a second BTreeMap and vector of item wrappers.
- Development/test builds optimize only Argon2, Blake2, and zxcvbn. The isolated, unchanged production-parameter Argon2 backup/unlock/rekey/restore/tampering test took **27.65s before and 1.80s after** in existing test binaries. The first optimized focused rebuild plus 70 tests took 43.89s overall (2.27s test execution); the previous focused run of 66 tests took 27.35s execution. This is a local sample, not a cold-build or cross-platform benchmark.
- Desktop vendor harnesses share a Cargo invocation. On Linux the combined package selection has exactly the same dependency feature rows as the separate selections. Workspace protocol harnesses remain separate because combining them changes feature resolution.
- Browser tests now use two file-level workers. All 38 tests and browser coverage gates passed. The single-worker baseline took 127.03s without coverage, while the two-worker coverage command took 78.06s. These runs have different instrumentation and command wrappers, so they establish an indicative improvement rather than an exact speedup ratio. Targeted Rust/extension test commands are documented in the contributor guide.

Broad debug-symbol reductions, GUI crate separation, paused-time worker tests, and the secondary opportunities remain deferred: they need additional evidence or have a larger correctness/debugging tradeoff. Full application debug information, production KDF parameters, coverage gates, and existing platform checks are retained.

### Final verification

The final sequential queue passed all eight steps; its temporary machine-readable report is `/tmp/check-queue-30ynroh8/result.json`.

| Check | Result |
| --- | --- |
| Shared validator | Passed: formatting, generated bundles/docs/contracts, 212 extension tests and coverage gates, vendor tests, 232 library tests, 172 binary/desktop tests, 31 CLI integration tests, two protocol tests, Clippy with warnings denied |
| CLI-only compilation | Passed with `--no-default-features --all-targets` |
| Desktop build | Passed |
| Browser, one worker | 38 passed, no skips |
| Browser, two workers with coverage | 38 passed, no skips; 85.16% content runtime byte coverage, 75.14% aggregate browser byte coverage |
| Go race tests | Passed, including the new transfer/reservation regressions |
| Go vet | Passed |
| Two-device integration | Passed: enrollment/credential recovery, download/unlock, automatic sync, concurrent-edit preservation, comparison download, and server restart durability |

The first shared validation after implementation took 174.83s, including 91s of main test compilation and 28.21s of Clippy preparation. This was a rebuild after source/profile changes; the original 109.3s validation used warm artifacts. Those total durations do not establish a build-speed improvement. Main library execution was 3.69s versus the original 30.32s; the separately isolated production-parameter test above provides the more controlled timing comparison.

`git diff --check` passed. No macOS/Windows execution, cold-build benchmark, fuzz run, or Rust LLVM coverage run was performed. The isolated native accessibility smoke check was not run because Xvfb is unavailable; the real software-renderer/layout tests passed. All coverage measurements here are from the existing extension gates, not a new Rust coverage claim.

## Original review evidence

- `npm run validate` passed locally in **109.3 seconds**, using existing build artifacts, Node 26.13.0, and the working tree's tests. Log: `/tmp/agent-check-_b9o6mzt.log` (temporary).
- Extension coverage: 212 tests passed; 77.53% lines, 91.78% branches, 91.83% functions, with the validator's per-file gates passing.
- The main Cargo test command reported **0.36 seconds** of build preparation. Library tests took 30.32 seconds, binary/desktop tests 25.46 seconds, CLI integration tests 11.58 seconds, and protocol integration tests under 0.01 seconds. Clippy finished in 0.48 seconds. These figures are not a complete decomposition of the validator's wall time.
- [CI run on 2026-11-02](https://github.com/nelszack/PasswordManager/actions/runs/41545720571), commit `d5dffd048ffbea1571b7b2594247ab55ff063a4f`: Windows job 360s (validation 258s), Linux 229s (validation 151s), macOS 199s (validation 118s). Browser job 211s, including 31s building and 110s testing. Coverage job 148s, including 97s measuring coverage. These are one historical run, not measurements of the current checkout.
- That run's Windows CLI integration suite took 71.64s; Linux took 9.97s and macOS 14.17s. Investigate this platform-specific cost before assuming compiler changes will fix it.
- [Fuzz run](https://github.com/nelszack/PasswordManager/actions/runs/41545720628): installing cargo-fuzz took about 1s per job; the compile-and-fuzz step took 219–298s with a 60s fuzz budget. Tool installation is already cheap in this sample.
- Local `target/debug` occupies about 44 GiB. This is accumulated output across builds/features, not one binary's size or a measurement of reclaimable redundant output.

## Prioritized opportunities

### 1. Stop rereading an unchanged encrypted vault every two seconds

**High priority, confirmed repeated work.** `src/server/cloud.rs:22` reads the entire encrypted vault inside `VaultWorker::with_session`, copies the returned zeroizing buffer with `.to_vec()`, and later hashes the copy. The automatic loop at line 242 does this every two seconds when automatic sync is configured and the vault is unlocked; it only checks whether that vault's binding is enabled after taking the snapshot. On a sync attempt, `sync()` takes another snapshot.

Use the existing worker session/revision signals to avoid unnecessary snapshots. Retain the bounded periodic remote check and account for out-of-process changes with a watcher or bounded file fingerprint check. Keep the authoritative session/local-content rechecks before installing downloads. Move ownership of the ciphertext buffer instead of copying it, and reuse an initial snapshot where correctness allows. This removes full-file I/O, allocation, wiping, and hashing from unchanged polling cycles and reduces occupancy of the sole vault worker. Test idle sync, local edits during upload/download, lock/switch, disable/re-enable, and external replacement.

### 2. Reduce sync-server lock scope around network transfers

**High priority for concurrent clients, confirmed serialization.** `sync-server/main.go:160` takes the global mutex until the response returns. Both `http.ServeContent` at line 215 and upload `io.Copy` at line 253 execute under that mutex. A slow upload or download delays unrelated vault operations and event-generation reads, despite the 16 request slots.

Open the immutable download snapshot and validate its metadata under a short lock, then release the lock before serving its bytes. For uploads, stage outside the global lock, reserve bounded quota, and recheck the conditional version at commit under a per-vault lock. Preserve retention correctness, durability, quota accounting, and cleanup of failed uploads. Verify with a deliberately slow request alongside another vault's HEAD/list/events request, plus concurrent conditional PUTs under Go's race detector.

### 3. Eliminate repeated duplicate-suffix searches during import

**High priority for duplicate-heavy imports, confirmed quadratic case.** `src/vault/import.rs:353` generally uses hash indexes well. In the `KeepBoth` branch, however, every duplicate restarts suffix probing at 1. Importing many copies of the same name/username repeatedly probes all already-used suffixes. With k duplicates, this can require roughly k² membership probes despite the 100,000-item limit.

Keep a next-suffix cursor per base name/username during planning, checking the existing names set to preserve collision handling. Preserve the current visible naming sequence, preview/apply agreement, and mixed-name behavior. Benchmark increasing duplicate counts and test pre-existing suffixed names.

### 4. Cache GUI search results across unrelated view updates

**Medium priority, confirmed repeated work; visible latency unmeasured.** `src/gui/view.rs:670` filters all items and allocates a matching vector whenever the vault view is rebuilt. `src/gui/presentation.rs:236` lowercases the query repeatedly for each tested field and lowercases every candidate string. A one-second tick and status responses regularly update the application. Rendering is already paginated to 50 rows, so adding basic pagination would not address this work.

Normalize the query once per change. Cache matching item IDs against list generation, query, kind, and ordering, invalidating on edits, refreshes, lock, and switch. Consider a lazy widget boundary for the list after measuring view/layout costs. Keep cached data limited to already-visible summaries. Measure typing and idle updates with a synthetic large list; preserve selection, pagination, Unicode matching, and accessibility behavior.

### 5. Normalize server search filters once per request

**Medium priority, confirmed avoidable allocations.** `src/vault/query.rs:67` lowercases the free-text query inside the per-entry closure. Its `contains()` helper lowercases the same needle for each field, and URL filtering repeats this for every URL. Metadata access adds BTreeMap lookups while walking entries.

Create normalized filter values before scanning. Prefer iterating complete items to repeatedly resolving their metadata by ID where convenient. Start with this small change before adding a persistent search index, which would introduce invalidation and secret-retention concerns. Verify case-insensitive Unicode behavior and exclusion of secret custom-field values.

### 6. Reuse password-strength scores within an unlock session

**Medium priority, CPU cost requires measurement.** `src/vault/query.rs:3` runs zxcvbn for every entry in each weak-password filter. `src/vault/audit.rs:182` computes it again when building each audit snapshot, while the vault owner is occupied. Network breach checks are already concurrent and run after snapshot creation; the remaining synchronous strength scan is the opportunity.

Cache only the score against item ID/revision or a password-change generation. Clear it on lock/switch and invalidate when a password changes. Avoid retaining plaintext passwords or introducing persistent password hashes for the cache. Measure audit and weak-filter latency for unique and reused passwords; verify mutation invalidation and lock responsiveness.

### 7. Try two browser workers while preserving per-test isolation

**High-value test experiment, speedup unmeasured.** `playwright.config.cjs:5` fixes workers to 1 and disables full parallelism. The observed CI browser test step takes 110s. `extension/e2e/harness.cjs` creates unique temporary homes, profiles, logs, and coverage filenames; the real-stack fixture also uses separate vaults and loopback ports.

First try two file-level workers with full parallelism still disabled. Check CPU/memory use and repeated runs for port allocation races, native-host registration, extension focus, and coverage aggregation. Preserve real-native coverage and retries. Raise concurrency further only with evidence; sharing one browser between tests would weaken the current isolation.

### 8. Measure and reduce debug-symbol/linking overhead

**Compilation experiment, not a confirmed improvement.** `Cargo.toml` has no custom dev/test profiles. Desktop code lives in the main binary, so Cargo builds a normal binary for integration tests and a binary test harness containing the GUI. CI repeatedly links desktop dependency graphs; Windows is the observed critical path. The local warm-cache numbers show that this is not the dominant cost of every validation run.

Collect cold and one-file incremental `cargo build --timings` / `cargo test --timings` baselines. Trial `[profile.dev] debug = 1` and `[profile.test] debug = 1`, comparing build time, link time, disk usage, and remaining crash-symbolization quality. Keep profile settings consistent across build/test commands that should share artifacts. Do not enable release LTO as a build-speed fix. Splitting the GUI into a separate target/crate is a larger follow-up only if timings justify it.

### 9. Consolidate Cargo vendor test invocations carefully

**Medium priority for cold builds, experiment needed.** `scripts/validate.cjs:59` onward executes five vendor Cargo test commands serially on Linux, then the application's tests. In the warm local run, the vendor harnesses themselves finish in under a second combined; most of their elapsed time is command/build preparation. Separate package selections can also compile dependencies under different feature sets.

Trial one multi-package `cargo test --lib` command for the same platform-specific vendor packages. Compare `cargo tree -e features`, executed test names, cold timings, and artifact reuse before accepting it: combined feature unification can change what is tested. Keep the application's existing JSON artifact capture for generated CLI checks. Do not parallelize several Cargo commands into one target directory.

### 10. Give targeted testing a documented fast path

**Low-risk developer feedback improvement.** `npm run validate` deliberately includes extension coverage, all relevant vendor suites, the desktop harness, integration tests, generated checks, and Clippy. That is appropriate before integration but costs 109s even on this warm checkout. The unit tests already use reduced test-only KDF parameters (`src/encryption.rs:38`); replacing production KDF work everywhere is not an available shortcut.

Document boundary-specific iterations: filtered library tests with `--lib`, filtered desktop tests with `--bin pm`, and individual extension unit files, followed by the full existing validator once stable. Profile individual Windows CLI integration tests before restructuring them: current tests exercise subprocess and handle-lifetime behavior that mocks could miss. For deadline-only Tokio unit tests such as `src/server/worker.rs:577`, trial paused time with Tokio's test utilities; retain real-time integration coverage and explicitly synchronize spawn-blocking work. Do not delete behavior coverage merely to reduce counts.

### 11. Avoid rebuilding HTTP connection pools on every sync operation

**Medium/low priority, confirmed repeated construction.** `src/server/cloud.rs:48` rereads config and creates a new `CloudClient`; `src/cloud.rs:193` builds its blocking reqwest client. The event loop repeats this construction for each long poll, and ordinary sync operations construct separate clients.

Reuse a client keyed by endpoint/credential generation, invalidating immediately when settings or credentials change and releasing superseded secret material. Cloning an existing client already shares its connection pool. Measure repeated sync latency and verify reconnect/server-switch/revocation behavior. This is less urgent than eliminating full-file idle snapshots.

### 12. Stream the ordered persistence overlay instead of rebuilding an index

**Medium/low priority for large vaults, confirmed allocation; gain unmeasured.** `src/vault/persistence.rs:74` constructs a new BTreeMap of every item reference, applies the transaction overlay, then builds a vector of serialization wrappers. The source maps are already ordered. Each durable mutation must still serialize/encrypt the full vault under the current format.

Merge the live and staged ordered iterators, skipping selected live IDs and preferring staged entries, and serialize through a sequence wrapper. Preserve deterministic order and zeroization on errors. First benchmark this against encryption and fsync: replacing the file format with a journal is a much larger change and is not justified by this review alone. Transactions already clone only affected items, so a full-vault-cloning fix would target an issue that is already addressed.

## Secondary opportunities

- `sync-server/main.go:223`: every PUT walks and stats the entire retained snapshot tree while holding the global lock. If storage scale warrants it, maintain reserved/committed byte accounting initialized from disk at startup, updating it only at well-defined commit/prune boundaries. Preserve crash recovery and quota headroom.
- `extension/content_observer.js:35` scans every descendant to discover inputs and open shadow roots. Ancestor class/style changes can schedule large subtree scans. `extension/content_controls.js:59` separately schedules repositioning for broad page mutations; positioning alternates geometry reads and style writes across controls. Coalesce classification work and batch geometry reads before writes, but retain ancestor visibility and shadow-root coverage. Existing animation-frame batching and pending-root deduplication are already present. Browser profiling is needed before changing discovery semantics.
- `src/vault/browser.rs:177`: saved URLs are reparsed during matching. A session-scoped parsed-site cache could help repeated browser lookups. Preserve exact scheme/port, wildcard, IDN, public-suffix, and invalid-input checks.
- `src/gui/backend.rs:217`: status polling also lists the vault directory and pending-operation journal. Consider slower discovery or filesystem invalidation if many vault/journal files make polling measurable. Preserve discovery of external changes.

## Recommended order and validation limits

Start with unchanged-sync snapshots, duplicate-import suffixes, and query normalization. Then measure two browser workers and compiler profile changes independently. Address server transfer concurrency with dedicated race/slow-client tests because it changes synchronization and quota ownership.

Keep OS/architecture checks, accessibility behavior, production Argon2 parameters, zeroization, atomic persistence/fsync, fuzz budgets, and coverage gates. Existing improvements include reduced unit-test KDF settings, scoped transaction cloning, CLI-only cloud builds, software-only desktop rendering, main-only PR cache writes, bounded breach-request concurrency, and direct reuse of Cargo's executable artifact.

At the original review stage, only the shared validator was run; browser E2E, Go race/vet, two-device sync, native desktop/accessibility checks, fuzzing, Rust coverage, CLI-only compilation, and cold builds were not rerun. Historical CI evidence is explicitly dated. The implementation section above records subsequent checks and measured improvements separately.
