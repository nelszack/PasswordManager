# Architecture review

Reviewed 2026-10-18 against the pre-refactor checkout (`c1fe149`). Source line references below describe that historical implementation. The approved refactor is implemented on `refactor/architecture`; the README describes the current design. This is a design recommendation, not a security certification. Three independent reviews covered the vault/store, application/protocol, and browser extension; the primary review checked the consequential findings against source and ran the existing suites.

## Recommendation

Keep the local Rust daemon, thin native host, browser extension, and authenticated encrypted snapshot files. Make a coordinated breaking change to the domain model and API before adding more features. The main problem is that one item, one session, and one operation each have several competing representations. File splitting has helped readability, but it has not eliminated those competing models.

The highest-return change is a cohesive item aggregate, an explicit unlocked capability, and a typed application API. Then simplify the extension around that API. Replace the existing internal wire and vault schemas deliberately; there is no need to preserve abandoned command generations for installed users. Preserve any development vaults that matter through a verified export/import or a one-time converter before replacing the format.

## Findings and decisions

### 1. Make secret lifetime a property of the field type

**Confirmed memory-hygiene gap. Address first.** Many paths correctly use `Zeroizing`, and whole-vault cleanup is implemented. However, secret fields and request objects still contain ordinary strings, so early returns and detached values depend on manual cleanup.

For example, [`EntryChanges.notes`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/types.rs#L495) is an ordinary optional string. [`update_typed_entry_with_limit`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/vault/entries.rs#L145) destructures the update, wraps its password and custom fields, then returns for an unknown target. Supplied notes are dropped without explicit wiping. This is evidence of inconsistent cleanup, not evidence of a remotely exploitable disclosure.

Use a small redacted, zeroizing-on-drop `SecretString`/`SecretBytes` abstraction for passwords, private notes, OTP seeds, key material, revisions, and secret-bearing request/response fields. Require explicit exposure at serialization, cryptography, clipboard, and reveal boundaries. Avoid blanket `Clone` on secret-bearing application objects; make intentional copies visible. [`DuoCredentials`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/types.rs#L250) already provides a local precedent for automatic cleanup.

This requires Serde adapters and ownership adjustments. It reduces cleanup obligations across error paths, failed parsing, and future changes. It does not promise to erase OS buffers, browser strings, or all allocator copies.

### 2. Model one item as one aggregate

**Largest simplification opportunity.** [`Vault`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/vault.rs#L326) owns entries while [`RecoveryData`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/vault.rs#L244) owns separate history, trash, OTP, metadata, and Duo collections. Reading an item reconstructs relationships through [`EntryIndexes`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/vault/query.rs#L4). Transactions snapshot and restore multiple collections in [`transaction.rs`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/vault/transaction.rs#L11), and loading validates their cross-references in [`backup.rs`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/vault/backup.rs#L62).

Replace those parallel collections with one private map of complete items:

```text
VaultData
  items: BTreeMap<ItemId, Item>
  next_item_id

Item
  id, revision, kind, name, username, primary_secret, notes
  urls, custom_fields, password_history
  authenticator, duo_enrollment
  created_at, modified_at
  lifecycle: Active | Trashed { deleted_at }
```

Trash and restore become lifecycle transitions. Purge removes a complete object. History and authenticator state stay with the item they belong to. Use typed timestamps and validated authenticator configurations; parse URI/text formats at import boundaries. Keep IDs opaque in the public API and use fixed-width validated storage IDs rather than exposing `usize` as a cross-language contract.

Stage a changed item or a batch of changes without mutating live state, serialize the proposed document, and adopt the staged state if replacement commits. This removes most cross-collection rollback machinery. It does not remove the need for validation, bulk-import planning, or careful commit handling. A full-vault deep clone per edit would create unnecessary secret copies; stage only changed items and serialize the combined view.

### 3. Separate domain state, unlocked session, and durable storage

**Design weakness with a concrete API footgun.** [`VaultSession`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/vault/session.rs#L6) represents state with a boolean, optional credentials, and an optional vault. [`write_vault`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/vault/persistence.rs#L333) returns success without writing if no credential exists. Its comment says the running server avoids that combination; this review did not find a live-server data-loss path through it. Nonetheless, a persistence function should not silently mean “memory only.”

Use an explicit state transition API:

```text
Session = Locked | Unlocked(UnlockedVault)

UnlockedVault
  data: VaultData
  key: SessionKey
  store: VaultStore
  epoch: SessionEpoch
```

`UnlockedVault` is an application/runtime object. `VaultData` is pure domain state and does not know about paths, credentials, Tokio, or persistence. Split external unlock credentials from the cached encryption key; [`PasswordType`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/types.rs#L6) currently combines these responsibilities. Pure mutation tests operate on domain state; persistence tests use an explicit store, including a memory implementation where useful.

The store persists an explicit `VaultDocument { schema_version, vault_id, items, ... }`, validated on conversion into domain objects. It does not serialize the runtime vault directly as [`write_vault_with_limit`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/vault/persistence.rs#L358) currently does. Keep filename, session epoch, review keys, and pending jobs outside the durable domain document.

Preserve the distinction between failure before replacement and failure after replacement. A committed replacement with uncertain directory durability must adopt the new memory/key state and return an explicit receipt. A staged design that rolls back memory after that point would regress current correctness.

### 4. Replace text-shaped RPC and remove historical command variants

**Highest-value boundary change.** [`ServerCommand`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/types.rs#L171) contains several generations of add/get/secret operations, normalized in [`commands.rs`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/server/commands.rs#L37). [`UpdateWireArgs`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/types.rs#L514) exists to retain old positional fields. [`protocol.rs`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/protocol.rs#L8) has separate frame kinds for display text and exact data.

The daemon renders CLI lists, while vault methods produce management JSON strings. The native host reparses selected results in [`response_data`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/native_messaging.rs#L649), and the extension reparses other results in [`parseItems`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/extension/native_protocol.js#L23). [`--json`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/client.rs#L99) can therefore wrap rendered text instead of useful records.

Introduce one versioned application request/response contract:

```text
Request  { protocol_version, request_id, operation, payload }
Response { request_id, result: typed_data | typed_error }
Mutation { operation_id, expected_revision, changes }
Receipt  { operation_id, revision, commit_state }
```

Use explicit operation tags and named fields. One operation per use case replaces historical variants. Results are typed summaries, details, codes, reports, and receipts; human formatting belongs in the CLI adapter. CLI `--json` emits those records directly. Errors carry codes and structured commit state, with user-facing descriptions added at presentation boundaries. Secrets retain exact bytes without relying on special text frames.

Generate browser types and runtime validators from a single contract source. Generated types alone do not validate browser messages. Generate operation policy metadata too: sender role, mutation/read classification, and timeout class. The duplicated mutation lists in [`background_native.js`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/extension/background_native.js#L5) and [`native_messaging.rs`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/native_messaging.rs#L487) show why this matters. Separate protocol compatibility from the package release version.

Keep the current authenticated transport while replacing its payload contract. Retire old fixture expectations and add fixtures for the new protocol's explicit tags and fields. Wire schema and durable vault schema have independent version numbers.

### 5. Give mutations identity, revision checks, and bounded recovery

**Confirmed recovery gap; broader API opportunity.** [`background_native.js`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/extension/background_native.js#L73) intentionally retains a timed-out active request until a late reply or disconnect, preserving mutation order. If a live port never supplies either event, [`pump`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/extension/background_native.js#L49) never sends another request on that lane. A synthetic exercise of the production bridge confirmed that a second read expired without being sent. Normal server I/O timeouts can recover many delays; the permanent stall requires the port to remain connected without a matching response.

Simply clearing the active slot or retrying a write would lose the ordering guarantee. Instead, assign mutation IDs at the application boundary, pass them to the daemon, retain bounded results, and support operation-status lookup. Add expected item revisions so two manager windows cannot silently overwrite each other's edits.

At a bounded bridge recovery deadline, reconnect the host and reconcile the outstanding operation before allowing dependent writes. A request ID correlates a reply; an operation ID identifies the mutation across reconnections. Persist deduplication metadata atomically with the encrypted vault if the guarantee must survive daemon restart. Scope IDs to the vault, retain a bounded window, and report expired/unknown outcomes rather than guessing.

Preserve committed-but-durability-uncertain results. Local deduplication does not give exactly-once semantics for remote Duo approvals or clipboard effects. Those require their own reconciliation rules and can remain uncertain.

### 6. Reduce extension authority and make runtime ownership explicit

**Immediate surface reduction, followed by a maintainability refactor.** Production content code requests a background-owned prompt in [`content.js`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/extension/content.js#L64), yet [`background_router.js`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/extension/background_router.js#L87) still accepts direct credential saves/updates, plus the old iframe relay flow. Searches found no production content callers for those legacy routes. They bypass the newer prompt lifecycle inside the extension. This is unnecessary extension authority; it is not evidence that ordinary page scripts can invoke extension runtime APIs.

Delete obsolete direct-write and relay handlers after retaining the current iframe picker/prompt flows in browser tests. Content scripts should propose a save or request a selection; trusted extension UI completes the decision. Narrow pending navigation records to the username/context the current flow actually needs, removing the legacy password-bearing schema.

Keep the useful dependency-injected background services in [`background.js`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/extension/background.js#L9). Move frontend code to explicit module entrypoints, preferably TypeScript with generated boundary validation and a small bundler. A UI framework is optional. Replace manifest-order shared globals with a per-document controller and explicit controllers for item editing, secret reveal leases, and mutation recovery.

Specify worker restart behavior: cancel secret-bearing decisions, reject stale epochs, and close/invalidate orphan prompts. Persist only the minimum nonsecret recovery metadata. Existing session-backed username records can retain their current expiry/consume-once semantics.

Unify discovery and input/submission capture under the same controller for each supported document/shadow root. Today [`content_observer.js`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/extension/content_observer.js#L23) discovers open shadow roots, but [`content.js`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/extension/content.js#L34) captures events from the document using direct input targets. Root-local capture and composed-path handling need complete fill/save browser tests, beyond merely verifying that shadow inputs receive buttons.

### 7. Select a vault by identity, then authenticate it

**Remove an unnecessary product constraint.** Without an explicit selection, [`lookup_vault_in`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/vault/persistence.rs#L134) enumerates vault files and attempts decryption. Creation/rekey also reject reuse of a password across vaults. That makes credentials serve as resource discovery and adds KDF work as vault count grows.

Require or remember a selected/default opaque vault ID, then unlock that file. Allow independent vaults to use the same password. The existing explicit filename selection is a useful starting point. Keep directory-wide password discovery only as a deliberate recovery command if it remains useful. This changes the CLI workflow but makes identity, error reporting, and unlock cost predictable.

### 8. Give the live vault one worker owner and one inactivity deadline

**Follow the model/API work; do not lead with concurrency machinery.** All authenticated commands, including status and lock, wait on the same [`session mutex`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/server.rs#L344). The separate extension control host avoids native queue blocking but does not bypass that mutex. Every activity also creates another sleeping [`auto-lock task`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/server.rs#L188); generation counters invalidate old tasks without canceling their sleeps.

Use a bounded mailbox to a worker that owns `Session`, with one resettable inactivity deadline and explicit lock/shutdown priority. Serve nonsecret status from a published snapshot. Prepare expensive work outside the owner where possible, then validate the session epoch and item revision before committing. Preserve the existing good Duo prepare/network/finalize pattern.

An actor does not make an in-progress filesystem commit or cryptographic operation preemptible. Define safe commit boundaries and measure lock latency under slow disk, imports, unlock, and repeated requests. Do not split into multiple writable vault owners to make lock appear fast.

Publish versioned status events over an authenticated subscription, forwarded through the native host. This can replace [`two-second polling`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/extension/background_status.js#L5) and allow idle native lanes to close. Adaptive polling while a UI is open, with slower alarms otherwise, is a reasonable intermediate step. Connections are currently created lazily per lane; the resource issue is retaining them after use, not starting all three unconditionally.

## Target dependency structure

Start with private modules and a few meaningful boundaries. Extract crates where compiler enforcement helps; a crate for every feature would add administration without solving the model problems.

```text
CLI adapter ───────────────────────┐
                                  v
Browser UI/content -> worker -> native host -> authenticated RPC adapter
                                                   |
                                                   v
                                             application service
                                              /           \
                                      pure domain       store + effects
                                                       /      |       \
                                               encrypted file clipboard Duo
```

Suggested ownership:

- `core`: complete items, validated values, pure changes, queries, secret types. No Clap, filesystem paths, transport framing, terminal rendering, or browser APIs.
- `api`: versioned public DTOs, command policy, codecs, generated frontend contract. No runtime session keys or persistence internals.
- `store`: document conversion, encryption, bounded reads, private files, atomic replacement and commit receipts. Depends on domain; domain does not depend on store.
- `runtime/app`: session owner, use-case orchestration, timers, configuration, clipboard and Duo effects. Adapters call this service.
- `cli`, `daemon`, `native`: argument parsing/presentation, authenticated ingress, and browser framing respectively. They can remain modes of one binary. Reusable clients return `Result`; only the executable boundary chooses process exit codes.

In particular, move Clap-specific conversions out of shared [`types.rs`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/types.rs#L1), CLI argument conversion out of [`config.rs`](https://github.com/nelszack/PasswordManager/blob/c1fe14985e54c00ff25473eb44022f5cb270bde5/src/config.rs#L1), and process-global output/exit behavior out of the shared client. These are actual dependency inversions, not just naming preferences.

## Implementation sequence and completion checks

1. **Close the small gaps first.** Automatic secret cleanup; delete unused extension write/relay authority; explicitly bound native recovery without retrying uncertain writes. Check unknown-target/validation/parse error paths, request ordering, iframe flows, and restart behavior.
2. **Replace the data/session model.** Complete items, explicit locked/unlocked state, independent versioned vault documents, selected vault IDs, and one commit boundary. Retain fault injection and abrupt-process tests for pre/post replacement, rekey, HOTP counters, imports, trash, and restart. Prove that missing credentials cannot produce a successful persistent mutation.
3. **Replace the API end to end.** One typed contract through daemon, CLI, native host, and extension; remove legacy commands and text/JSON adaptation. Verify exact secrets, typed CLI JSON, sender policy, invalid envelopes, and incompatible versions. Add operation identity and revision conflicts here; finish bounded reconnect/reconciliation against the real daemon.
4. **Consolidate runtime ownership.** Single worker/deadline, published status, explicit frontend modules/controllers, and event-driven status when supported. Measure lock latency and test stale external jobs, worker restart, nested open shadow roots, and overlapping manager edits.

Each step should leave an executable vertical slice passing its existing checks. No compatibility window is required, but do not remove old adapters until their replacement slice works. Avoid one large untestable rewrite.

## What to preserve

The encrypted snapshot store is appropriate for this local product. Keep bounded inputs and KDF parameters, authenticated encryption/header checks, private temporary files, fsync and atomic replacement, explicit uncertain durability, secret-free list results, browser-derived origin checks, selected-item reveal, session-bound Duo decisions, and the meaningful existing regression/fuzz tests.

SQLite, per-record encryption, envelope encryption, microservices, a UI framework, and a new IPC transport are not prerequisites for these improvements. Revisit storage only after measuring snapshot write cost or introducing a product requirement such as concurrent writers/sync. The present architecture already has good storage safety mechanics worth carrying forward.

## Implementation follow-up

The implementation was checked against all eight recommendations after the
refactor, with separate reviews of the core, runtime/protocol, and extension.
That pass found and corrected multi-vault deletion selection, trash display IDs
that disagreed with restore/purge, and full-range HOTP counters that JavaScript
could not represent exactly. History and trash now also have typed response
records; acknowledgement strings are never guessed to be JSON.

The design uses the alternatives allowed above: private modules within one
crate, explicit CommonJS frontend entrypoints with a dependency-free bundler and
generated TypeScript boundary declarations, and adaptive status polling while UI
clients are open. Authenticated status subscriptions are not implemented.

Operation receipts are bounded to 256 records in a running daemon. Cached
results are limited to 64 KiB each, and locks discard secret result bodies.
Receipts do not survive daemon restart; unknown outcomes require inspection and
explicit acknowledgement without replay. Control priority and independent status
are tested with a blocked owner, but filesystem/KDF work already in progress
still determines the time until a lock can complete at a safe boundary.

The README documents the incompatible development vault format and the original
binary's portable export/import path. No legacy vault decoder or automatic
migration is included. Local tests use isolated vaults; existing personal vaults
are not part of verification.

Final local verification passed `npm run validate` (238 Rust tests, 166 extension
unit tests, formatting, generated artifacts, syntax/coverage gates, and strict
Clippy), all 39 browser end-to-end tests, and the Rust coverage gate with
79.76% line coverage. Browser coverage is 77.22%, with 85.33% for the content
runtime. Cross-platform checks and coverage-guided fuzzing run in GitHub CI.

## Review-time verification and reference material

Executed in this checkout:

- `cargo test --locked --all-features`: **267 passed** (241 library, 4 binary, 21 CLI integration, 1 protocol compatibility).
- `npm run test:extension`: **153 passed**.
- Synthetic native bridge exercise: a connected host with no response leaves the next request unsent until it expires.

The original review was read-only apart from documentation. Browser E2E, fuzzing, cross-platform checks, coverage, and the full validation command were not rerun during that review; the implementation and its validation followed after approval.

Primary references checked for the proposed mechanisms:

- [Tokio shared-state guidance](https://tokio.rs/tokio/tutorial/shared-state): documents both mutex ownership and a dedicated task accessed through message passing. The worker proposal is an application-specific judgment, not a claim that mutexes are inherently wrong.
- [Serde enum representations](https://serde.rs/enum-representations.html): explicit tagged representation options for the new contract.
- [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging): framing, host process connections, and extension messaging boundaries.
- [Chrome extension service-worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle): native connections can keep a worker alive; persistent worker globals are still not a restart guarantee.
