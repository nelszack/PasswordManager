# Mobile and passkey implementation checklist

This is the acceptance checklist for `feature/android-passkeys`. Checked boxes
mean software is implemented with source/build/test evidence recorded below.
They do not imply physical-phone acceptance: device checks remain separate from host tests. Never use a personal vault in tests.

Current delivery, **2026-11-16**: Android **0.3.0 (12)** is installed on the
physical test phone (Android 13, ARM64). Eight isolated phone runs passed for management,
the redesign, autofill and noninteractive biometric regressions. Light/dark and
1.7 font-scale checks passed on the isolated API 36 emulator. The
[0.3.0 verification record](#version-030-usability-verification-2026-11-16)
lists exact scope and evidence. Older version records below are historical;
their test counts and installation status describe those builds only.

Current delivery is an Android development APK. Release acceptance is incomplete
until the physical-phone checks below pass. Legacy Chrome autofill can use an
explicit exact-hostname account/address picker when Android omits the page port;
that mode cannot verify the current port. Other browsers require a full native
origin. Do not assume every browser is compatible before testing it.

## Agreed scope

Android first; iPhone later. A native vault app and website autofill are required.
There is no hosted web vault. Existing desktop vaults and the encrypted snapshot
sync server remain the source of interoperable vault data. Distribution is a
privately signed APK, installable by USB/ADB or Android's package installer.

The requested mobile target is near parity with the CLI and desktop GUI for
user-facing vault operations. Android should be usable independently for daily
management and recovery, rather than requiring a desktop for missing tools.
Desktop process control, shell completion, native-messaging registration, and
Linux shortcuts are platform-specific and do not need mobile equivalents.

## Shared vault and compatibility

- [x] A mobile API uses the existing Rust encryption, vault format, entry rules,
  generators, OTP implementation, and sync protocol without a desktop daemon.
- [x] Open existing password and external-key vaults; create password vaults.
- [x] List/search, reveal/copy, create/edit/delete all eight supported item types, including multiple URLs and custom fields.
- [x] Keep keys and secrets out of logs, debug formatting, and error messages.
- [x] Locked operations fail; lock drops decrypted entries and session keys.
- [x] Existing desktop clients preserve passkeys across edits, sync, and backups.
- [x] Portable exports preserve passkeys; lossy CSV exports explain omissions.
- [x] Regression tests use synthetic vaults and verify desktop/mobile compatibility.

## Android application and lifecycle

- [x] Native Android project packages the Rust library and has reproducible build instructions.
- [x] All vault files live in app-private storage; cloud backups and screenshots are disabled.
- [x] Unlock, vault selection, search, editing, generator, OTP and explicit lock UI.
- [x] Backgrounding, screen lock, and inactivity clear the unlocked session, except the bounded same-site grant after a completed autofill handoff described below.
- [x] Long-running encryption and network operations run off the main thread.
- [x] Vault state has its own Rust mutex, held only for local steps. Sync, Duo push and
  breach-check network transfers run between a snapshot/prepare step and an apply step that
  re-checks the unlock session (and, for sync, the engine's file/checkpoint digest), so they
  never block autofill or passkey requests. Autofill and credential-provider service requests
  (including form parsing) use their own thread; asset-link checks use another.
- [x] Passkey creation and saves from other apps return their result first; a coalescing
  follow-up sync then runs on a separate thread. It snapshots the encrypted vault while still
  unlocked and may finish that upload after the app locks; anything it would apply still needs
  the same unlock session, so a download waits for the next unlock.
- [ ] Verify on a device that autofill stays responsive during a slow sync and that a
  follow-up sync after a passkey/password save reaches the server.
- [x] Import an existing encrypted vault and external key through Android's file picker.
- [x] Export encrypted backups and inspect all imported item types without data loss.

## Mobile usability

- [x] Consistent Vault/Tools/Settings navigation, Back and Lock actions, and progress feedback.
- [x] Live search, scrollable type filters, readable account rows and clear empty states.
- [x] Group item details with explicit reveal/hide and copy actions; hide secrets initially.
- [x] Keep editor Save/Cancel reachable, confirm draft discard and retain inputs on failed saves.
- [x] Group settings with readable values, units, explanations, valid ranges and edit validation.
- [x] Support Android light/dark appearance, larger text and keyboard/system-bar insets.
- [x] Discard stale screen callbacks after navigation without weakening background locking.

## Biometric unlock

- [x] Enable only following successful password/key unlock and explicit opt-in.
- [x] Wrap the vault key with an Android Keystore authentication-per-use key.
- [x] BiometricPrompt authorizes the actual unwrap operation using a CryptoObject.
- [x] Require strong biometrics; device PIN fallback is not enabled implicitly.
- [x] Bind the protected key to its vault and encryption header; reject stale keys after rekey.
- [x] Disable/invalidate the protected copy after enrollment changes or user disable.
- [x] Original password/key remains the fallback; biometric data never leaves Android.
- [ ] Verify enrollment, cancellation, biometric failure, process restart, and invalidation on a device.

## Password autofill and saving

- [x] Register an Android AutofillService with system-controlled access.
- [x] Negotiate Android inline keyboard suggestions with dropdown fallback, expose only an unlock chip while locked, and provide account chips only within an authorized site session.
- [x] Use a secure compact bottom sheet for unlock/account choice, automatically offer configured biometrics, and fill directly after tapping a current named account suggestion.
- [x] Keep secrets out of suggestion datasets until selection, revalidate account/vault/site metadata on tap, and return stale suggestions to the chooser.
- [x] Parse username/password fields including nested browser structures.
- [x] Require an explicit account choice and unlock before releasing credentials.
- [x] Reuse a completed autofill unlock for the same caller/site for up to five minutes; revoke on expiry, cancellation, non-completed backgrounding, management access, screen-off, explicit lock, or restart.
- [x] Recognize explicit verification-code fields and fill fresh site-matched TOTP codes; support code-only entries and never consume HOTP counters.
- [x] Offer explicit copy actions for username, password, and fresh verification codes, with sensitive clipboard metadata and bounded, ownership-checked clearing.
- [x] Match HTTPS websites using the existing origin policy when full origins are available; reject HTTP and ambiguous origins.
- [x] Trust browser-reported origins only from verified browser package certificates.
- [x] Preserve origin ports using a native browser address-bar value. Never trust HTML URL attributes.
- [x] When release-signed Chrome supplies only a hostname, require vault unlock (or the bounded same-site grant above) and explicit exact-hostname login/address selection; display saved ports and reject wildcard/parent/sibling matches. This user-approved mode cannot verify the current page's port and does not change desktop origin checks.
- [x] Native-app matching binds saved approval to package name and signing certificate.
- [x] Offer save/update after submission with an explicit confirmation and duplicate handling.
- [ ] Verify Chrome multi-step logins, iframes, cancellation, wrong origins and offline filling on a device.

## Passkeys

- [x] Generate ES256/P-256 credentials using a maintained cryptographic implementation.
- [x] Encrypt private key material inside the vault; synchronize and back it up with the vault.
- [x] Validate RP ID, origin, challenge, user handle, supported algorithms, and exclusions.
- [x] Construct WebAuthn registration responses with COSE public keys and `none` attestation.
- [x] Construct signed authentication responses with UP/UV and backup flags.
- [x] Use discoverable credentials, allowCredentials filtering, correct user handles,
  and a synchronized-credential signature counter policy.
- [x] Verify assertion signatures in tests using the registration public key.
- [x] Android 14+ CredentialProviderService supports create/get password and public-key credentials.
- [x] Obtain the final caller identity from Android; accept delegated browser origins only through a trusted signer allowlist.
- [x] Validate native app to RP association through Digital Asset Links before passkey creation/use.
  Verdicts are cached in memory (authorized for an hour, refused for three minutes; network
  failures are not cached); signer digests are cached until the calling package's version or
  install/update time changes; the trusted-browser list is parsed once per process.
- [x] Listing and registration read only passkey identities (never private keys) and skip a
  damaged record instead of failing; sign-in loads and fully validates only the selected record.
- [x] User verification and explicit consent precede every passkey operation.
- [x] Cancellation and excluded/unsupported credentials return the appropriate provider errors.
- [x] List and delete passkeys without exposing private key material in the normal interface.
- [x] Preserve passkeys on portable JSON import/export; warn about unsupported external passkey formats.
- [ ] Test registration and sign-in with a real HTTPS relying party on Android.

## Sync and migration

- [x] Configure HTTPS sync endpoint and a per-device credential stored encrypted by Android Keystore.
- [x] Surface underlying transport errors and explain that failed first connections require re-entering the cleared device credential.
- [x] Package the complete, Cargo-version-matched Android TLS companion and its certificate-revocation network policy.
- [x] Defer authenticated-cipher AAD until biometric success; handle provider/callback errors and discard authentication results after backgrounding.
- [x] Show per-vault biometric enabled/disabled status on home, Settings, and unlock screens, with matching setup controls and an unavailable unlock action disabled.
- [x] List/download existing cloud vaults and check their encrypted identity before accepting them.
- [x] Synchronize unlocked changes with optimistic concurrency; preserve both sides on conflicts.
- [x] Retry safely after offline operation or uncertain upload acknowledgement.
- [x] Provide conflict review/recovery without silently overwriting either copy.
- [x] Google CSV import uses the existing preview and conflict policies; document reviewing other password managers for unique items.

## Private distribution

- [x] Provide debug/release APK build paths, with release signing supplied by the owner.
- [x] No production signing keys, vaults, or device tokens are committed.
- [x] Document ADB installation/update, same-key upgrades, signing-key backup, and Android verification constraints.
- [x] Successful host Rust tests and Android compile/package check recorded below.
- [ ] Install and upgrade a privately signed release build on a physical phone, preserving the encrypted local vault (debug upgrades have been exercised).

## Extended mobile management

- [x] Native Tools & recovery menu for history, trash/restore/purge, full typed-item editing, advanced search and audits.
- [x] Configurable password/passphrase generation and local strength assessment, including standalone use while locked.
- [x] TOTP/HOTP setup/removal and explicit counter-consuming HOTP generation; Duo enrollment and reviewed push decisions reuse shared validation.
- [x] Byte-based complete encrypted backups and independent-identity restore; CSV/JSON transfers with preview and conflict choices.
- [x] Import approvals bind file digest, local revision and policy, and expire when locked or consumed.
- [x] Document destinations are selected before generating export contents; picker return reauthenticates before unlocked exports.
- [x] Original-credential-gated credential changes/deletion; rekey preserves a local encrypted recovery copy and disables biometric enrollment through the UI.
- [x] The rekey recovery copy is a complete vault still encrypted with the **old** password or
  key file. After the first original-credential unlock with the new credentials, the app offers
  once to delete it, warning that anyone with the old credentials can open it; Vault
  credentials → "Delete old-password recovery copies" remains available. Copies made by earlier
  builds are not attributed to a vault and are left alone. With sync, the server also keeps (by
  default) two earlier snapshots per vault; ones uploaded before the change stay encrypted with
  the old credentials until newer uploads replace them, or an administrator removes them.
- [x] Deleting a local vault also removes its `<vault>.sync.json` checkpoint (server URL and
  vault ID).
- [x] Settings persist in app-private storage; auto-lock, clipboard, history and generator use configured values. Trash age-based purging requires an explicit action.
- [x] Per-vault sync status/check, enable/disable, and comparison downloads; comparison and rekey-recovery copies require explicit sync enabling.
- [ ] Complete the per-feature hardware and desktop round-trip acceptance in the matrix below.

## Later interoperability work (not implemented by the initial Android adapter)

- [x] Desktop browser passkey creation/sign-in integration and its security tests (Chromium end-to-end test registers, signs in, and verifies the signature; Firefox acceptance pending).
- [ ] Android Credential Exchange import/export for direct Google and other provider transfers.
- [ ] External passkey import formats, including supported Bitwarden/FIDO CXF key representations.
- [ ] PRF/largeBlob extensions, related-origin requests, and cross-device QR authentication.
- [x] Mobile payment-card and identity autofill (explicit choice per fill; shared Rust field rules). Device acceptance with real checkout and address forms is still pending.

## Mobile feature parity roadmap

Source comparison: `src/cli.rs`, `src/gui/model.rs`, `src/gui/workflows/`,
`src/gui/generator.rs`, `src/vault/mobile.rs`, and Android `MainActivity.kt`,
reviewed 2026-11-16. "Available" below describes implementation, not complete
hardware acceptance. Missing features are now part of the requested parity
target; they are not completed by preserving their data in the encrypted vault.

| Capability | Mobile 0.3.0 implementation | Acceptance still required |
| --- | --- | --- |
| Basic logins | Create/edit, reveal/copy, notes, search, delete | Complete Chrome sign-in/save and Google MFA flows |
| All eight item types | Native create/edit for logins, notes, cards, identities, Wi-Fi, licenses, SSH keys and API secrets | Physical editing/desktop round trips across representative types |
| Rich metadata | Multiple websites and ordinary/secret custom-field editing | Stale draft rejection, preservation of unrelated fields, background clearing |
| Generation and strength | Standalone configurable generator, passphrases, defaults and local assessment | Native screen checks; user preferences and clipboard expiry |
| Search | Live vault search/type chips; advanced text/name/username/site/notes and type/health filters, sorting | Filter results agree with desktop for the same synthetic vault |
| TOTP setup | Set/change/remove Base32/otpauth authenticators; show/copy and site autofill | Complete real-browser MFA and setup cancellation |
| HOTP | Explicit, confirmed next-code action persists the counter; automatic filling never advances it | Device persistence and offline/conflicting counter changes |
| Duo | Enrollment, HOTP/TOTP mode, pending-request review, explicit approve/deny and Verified Push input | Real provider enrollment/push tests with a dedicated test account |
| History | List password revisions and restore a selected revision | Device restore and desktop compatibility |
| Deleted items | Browse, restore, confirmed purge, explicit application of retention settings | Device restore/purge and conflicting-name behavior |
| Vault health | Weak/reused/duplicate/stale/missing-authenticator reports and opt-in online breach checks | Offline/partial network reporting and screen acceptance |
| Complete backups | Dedicated password/key-protected backup containers and independent-identity restore; encrypted snapshot transfer | Physical document I/O and restart recovery; desktop compatibility |
| Portable migration | CSV/JSON preview and policies, file/revision-bound approval, explicit plaintext export | Real system picker, cancelled/changed imports and format-loss review |
| Vault credentials | External-key generation/save/create, original-credential-gated rekey/deletion, encrypted pre-rekey recovery copy | Interrupted rekey, original-key recovery, biometric invalidation, two-device rekey recovery |
| Sync | Connect/list/download/sync/conflict review plus status/check, enable/disable and disabled comparison downloads | Full two-device/offline acceptance and credential-rotation recovery |
| Preferences | Grouped readable summaries and validated explanatory dialogs for generator defaults, auto-lock, clipboard expiry, history and explicitly applied trash retention | Persistence across restart; scoped autofill grant remains at most five minutes |
| Passkeys | Android 14+ provider; private fields protected from ordinary editing | Real relying-party provider use on Android 14+; Android 13 storage tests are not provider tests |

These native workflows expose shared Rust operations through the mobile API. Reuse existing validation, encryption, history, import,
audit, and conflict policies. Android file operations must use the system picker
and bounded byte/stream interfaces rather than assume desktop filesystem paths.
Do not run the CLI or desktop daemon inside the phone app.

Implementation order; remaining acceptance stays separate:

1. Current autofill/TOTP, biometric fallback, sync and recovery flows are implemented;
   complete the interactive/browser/two-device acceptance below.
2. History/trash/restore, complete backup recovery, credential changes and
   external-key creation are implemented; retain interrupted-operation and recovery checks.
3. Typed-item/custom-field/multiple-website editing and authenticator setup,
   including explicit HOTP advancement, are implemented.
4. Generator/passphrases, advanced search, health reports, settings, portable
   imports/exports and sync controls are implemented.
5. Duo management screens are implemented; live provider acceptance and Android
   14+ passkey-provider acceptance remain pending. iPhone remains a later platform
   phase, using the same shared operations.

For each capability, track implementation, shared/mobile tests, and phone
acceptance separately. Completion requires a native UI, an accessible error and
cancellation path, synthetic success/failure tests, correct lock/background
behavior, and a desktop-to-phone-to-desktop round trip that preserves unrelated
fields, authenticators, passkeys, history, and trash. Destructive/rekey/import
workflows also need interrupted-operation and recovery tests. Do not mark the
whole mobile app accepted merely because an APK builds or a shared Rust test passes.

## Later iPhone phase (not part of the Android release)

- [ ] Swift interface and generated/native bridge to the same Rust mobile API.
- [ ] Keychain biometric key protection with Face ID/Touch ID enrollment invalidation.
- [ ] Password AutoFill credential provider extension, including passkeys.
- [ ] App/extension sharing, locking and encrypted sync verified on hardware.
- [ ] Private signed installation and provisioning renewal instructions; no App Store publication.

## Verification evidence

### Initial adapter verification (2026-11-15)

Validated on Linux and an isolated Android 16/API 36 x86_64 emulator on
2026-11-15. No personal vaults were used.

- `npm run validate`: passed, including extension coverage, shared Rust tests,
  desktop/application tests, 32 CLI integration tests, generated contracts/docs,
  formatting, and strict Clippy. Two opt-in performance workloads were ignored.
- After final mobile hardening, `cargo test --locked --all-features --lib`:
  225 passed, zero failures, one opt-in performance workload ignored.
- `cargo check --locked --no-default-features --all-targets`: passed.
- Strict Clippy for `password_manager` and `pm-mobile`, all features/targets: passed.
- `python3 scripts/build_android.py`: built both ARM64 and x86_64 JNI libraries
  and a debug APK; three Android unit tests and lint passed. Lint advisories remain;
  they are not treated as physical-device evidence.
- APK v2 signing and 16 KiB native-library/package alignment verified.
- APK installation and launch on the emulator succeeded. Both final packaged JNI
  instrumentation tests passed (zero failures), including browser-supplied hashes
  and rejection of authentication work scheduled after an activity stops.
- `actionlint .github/workflows/android.yml`: passed. Remote GitHub CI has not
  run because this branch has not been pushed.

Evidence is reproducible from the commands above and the tests in
`src/passkey.rs`, `src/vault/mobile.rs`, `src/vault/mobile_sync_tests.rs`, and
`android/app/src/{test,androidTest}/java/dev/nelszack/passwordmanager/`.
The Android tests cover independent JCA verification of the emitted COSE public
key and assertion signature, including the browser-supplied client-data hash.
The lifecycle test rejects late work scheduled after an activity has stopped.
They do not simulate a fingerprint sensor or prove real-browser autofill.

### Physical-phone acceptance (record device, OS, browser, date, and result)

Partial connectivity evidence, 2026-11-15: physical test phone, Android 13/API 33,
ARM64. Debug update installation preserved app
data. The isolated `SyncConnectivityTest` reproduced the pre-fix TLS failure
(`invalid peer certificate: Revoked`) and passed both tests with version 0.1.2:
the merged policy denies general HTTP while allowing CA revocation-list hosts,
and the real HTTPS sync endpoint returns the expected unauthorized response for
a dummy credential. No personal vault or saved device credential was opened.
This verifies transport only; downloading/unlocking a synced vault, browser
autofill, biometric invalidation, and complete two-device sync remain separate
acceptance work below.

Biometric regression evidence on the same phone, version 0.1.3: all four
`BiometricUnlockTest` cases passed, including two real fingerprint prompts for
enrolling a synthetic vault key, decrypting it, and unlocking that synthetic
Rust vault. The other cases verified that callback/provider exceptions do not
crash the activity, results from before a background/resume cycle are discarded,
and rejected enrollment clears its key material. Storage was isolated under a
temporary cache directory; the synthetic biometric key was removed afterward.
The original crash was an auth-per-use Keystore operation receiving AAD before
authentication, then throwing `IllegalBlockSizeException` from an unguarded
success callback. Both enrollment and unlock now defer AAD until authentication.

Hostname-picker regression evidence on the same phone, version 0.1.6:
`AutofillHostnameTest` passed against a synthetic cache-only vault. It checks
locked access, password-free candidate metadata, rejection of a lookalike
hostname, and exact-port secret checks after selecting a saved address. Host
validation also passed 226 Rust library tests (one opt-in benchmark ignored),
strict mobile Clippy, four Android unit tests, and Android lint. The approved
hostname-only policy is limited to release-signed Chrome; full-origin flows
and desktop matching retain their existing port checks.
On Chrome 157.0.8103.78, the public `accounts.google.com` email step reproduced
the old missing-address rejection with no native address metadata. Version
0.1.6 ignores its hidden field and successfully prepares an authenticated
hostname-only response for the visible email field. This confirms request
acceptance; complete multi-step filling and the remaining browser acceptance
cases below require separate verification.

Version 0.1.7 session/TOTP evidence on the same phone:
`AutofillSessionLifecycleTest` passed using a cache-only synthetic vault. A
completed handoff retained the native unlock, while cancelled/backgrounded
pickers, opening management, and explicit lock revoked both the grant and
native session. `AutofillHostnameTest` also passed in a separate process.
Six Android unit tests cover grant expiry/caller/site isolation and explicit
verification-code hints, and 227 Rust tests (one opt-in benchmark ignored)
include site/port checks for TOTP-only entries and rejection of HOTP. Android
lint and strict mobile Clippy passed. Clipboard actions use Android's sensitive
metadata and ownership-checked expiry; a complete Google MFA flow and clipboard
behavior under OS process suspension remain separate hardware acceptance.

Version 0.1.8 interaction evidence, 2026-11-16: the SHA-256-verified
ARM64 debug update installed on the same test phone as version code 9, preserving
app data and the selected autofill provider. `AutofillHostnameTest` passed in an
isolated cache-only process. The test APK was removed afterward and the manager
was force-stopped/reopened to reset JNI's temporary storage binding.
Earlier phone presentation and lifecycle attempts with the keyguard still showing
failed their layout/handoff assertions; those attempts are not acceptance passes.
After unlocking the phone, `AutofillPresentationTest` passed, verifying inline
style negotiation, compact bottom placement, bounded height, and screenshot
protection. These UI tests now explicitly require an unlocked device. Chrome
keyboard presentation and the automatic fingerprint flow remain pending on this
phone.

The unlocked phone also passed `AutofillDirectFillTest` and
`AutofillSessionLifecycleTest` in separate instrumentation processes, with the phone's
vendor keyboard selected. Tapping the synthetic account suggestion filled both username
and password without another picker. The session check verified completed-handoff
retention and cancellation, management, and explicit-lock revocation. The direct
fill test searches all interactive accessibility windows because the initial
active-window-only lookup missed the suggestion window. The test APK was removed,
the temporary screen-awake setting restored, and the manager reopened afterward.
These native-form checks do not establish Chrome/Google MFA acceptance.

On an isolated Android 16/API 36 x86_64 emulator, three separately run tests passed:
`AutofillPresentationTest` verified inline style negotiation, unsupported-style
and capacity fallback, bottom placement, bounded height, and screenshot protection;
`AutofillDirectFillTest` tapped a real Android account suggestion and verified both
synthetic username and password values without another picker; and
`AutofillSessionLifecycleTest` verified handoff retention and cancellation,
management, and explicit-lock revocation. The separate synthetic client uses only
framework Java classes and returns assertion bits, never field values, to the
test. APK builds, seven JVM tests, and Android lint passed. These synthetic checks
do not prove Chrome or vendor keyboards' inline rendering or a complete Google
MFA flow; the device scenarios below remain required.


Version 0.2.0 parity evidence, 2026-11-16: version code 10, ARM64
development debug APK, SHA-256 verified before updating the same test phone
without uninstalling the main app. Installed APK SHA-256:
`f01224e32f514ed5fe3f7b2c040f7fab13fe615204a43b9fabc7fc9ca3f46138`.
Eight separately isolated on-phone checks passed:

- `MobileParityNativeTest`: external-key vault creation/unlock, typed metadata,
  password history/restore, trash/restore/purge, TOTP/HOTP configuration and counters,
  encrypted backup/import/export, original-credential rekey enforcement, actual
  password rekey, independent backup restore, search/audit, and passkey-data preservation.
- `MobileParityTest`: native typed Wi-Fi editing with multiple URLs and a secret
  custom field, trash restore, HOTP screen without automatic counter consumption,
  configurable generation, and complete backup/restore with history preservation.
  Document I/O used a private debug provider and intercepted picker; it did not
  browse personal files or establish real system-picker acceptance.
- `AutofillPresentationTest`, `AutofillDirectFillTest`, and
  `AutofillSessionLifecycleTest`: compact secure sheet, both filled credentials,
  scoped handoff reuse, and cancellation/management/lock revocation.
- The three explicitly selected noninteractive `BiometricUnlockTest` methods:
  callback errors/stale results, asynchronous UI errors, and rejected-enrollment
  material clearing. The interactive fingerprint test was not requested or run.

The final shared library passed 234 tests (one opt-in benchmark ignored), strict
Clippy including `pm-mobile`, and CLI-only compatibility checks. `npm run validate`
also passed on this implementation before the final mobile cancellation hardening,
including extension coverage, CLI/GUI tests, CLI integration and generated contracts;
the final library and Clippy runs include that hardening. Seven Android JVM tests,
Android lint, fresh ARM64 JNI/APK builds and test-APK packaging passed. The release
manifest excludes the debug fixtures/provider and keeps Android backups disabled.
Native lock signaling bypasses the vault mutex, wakes pending network futures through a
notification (no polling) and checks cancellation between audit entries; host tests exercise interruption and
session clearing. Remote changes may already have completed when interrupted,
so uncertain operations must be inspected before retrying.

All phone fixtures used UUID cache-only vault storage. The UI fixture overrides
post-mutation sync so no test records reach the saved server. No real vault,
saved device credential, personal document or clipboard value was read for these
tests. The test APK was removed and the manager restarted after each queue. The
original USB-awake setting was restored and read back successfully at the end
of verification; the selected autofill service remains Password Manager.

Still unverified on this build: full Chrome/Google MFA and save/update flows,
real system document-picker handling, live Duo enrollment/push, new interactive
fingerprint/invalidation scenarios, real two-device/offline/rekey recovery, and
privately signed release upgrades. The Android 13 phone cannot verify Android 14+
passkey-provider operation; its passkey checks above cover shared storage and
backup behavior only. iPhone remains unimplemented in this Android phase.

Version 0.2.1 settings clarification: every numeric preference has a persistent
label, units, default, valid range and plain-language explanation; history/trash
zero values and explicit trash purging are explained. Numeric keyboards and
field-specific validation reject invalid values before saving. This is a UI
clarification; stored values and Rust settings semantics are unchanged. Android
APK assembly and lint passed; no additional personal-vault testing was needed.
The 0.2.1 installation attempt was blocked because the host computer did not
detect the phone over USB; at that time, 0.2.0 remained installed. The 0.3.0 installation
below supersedes this historical status.

### Version 0.3.0 usability verification (2026-11-16)

This update supersedes the pending 0.2.1 installation above. Version **0.3.0 (12)**
was installed with `adb install -r` on the test phone (Android 13, ARM64), retaining
the existing app data. APK SHA-256:
`53eb95a5b86b5904b78d6307db404edbb799ab65cda11e6c7841ab0177dcc5fb`.

- Debug APK and instrumentation APK assembly, all eight JVM tests, and Android
  lint passed (zero errors; 31 warnings). No Rust source changed for this redesign.
- The isolated API 36 x86_64 emulator passed `MobileRedesignTest` in light mode
  and in dark mode at 1.7 font scale. Synthetic screenshots of the vault,
  details, tools, settings and editor were inspected; no personal screen was
  captured. Phone windows retained screenshot protection.
- Eight isolated phone runs passed: `MobileRedesignTest`, `MobileParityTest`,
  `AutofillPresentationTest`, `AutofillDirectFillTest`,
  `AutofillSessionLifecycleTest`, and the three noninteractive biometric methods
  listed in the 0.2.0 evidence above. These exercise actual redesigned management
  screens, typed editing/recovery/backup, autofill presentation/direct filling,
  session revocation and biometric error handling with cache-only synthetic vaults.
- The release manifest was generated and checked: debug fixtures/providers are
  absent and Android backups remain disabled. Release signing/upgrade acceptance
  still requires the dedicated private signing key.
- Test storage was isolated from the real vault and post-edit sync was disabled
  by the UI fixtures. The test APK was removed, the USB stay-awake preference
  restored, and the manager force-stopped/reopened to restore normal JNI storage.

The outstanding real-provider/device acceptance checks listed above still apply;
this update does not establish live Google MFA, fingerprint enrollment, Duo,
two-device recovery or Android 14+ passkey-provider acceptance.

Test maintenance, 2026-11-16: eight cache-only instrumentation classes now share
`SyntheticVaultRule`, and the management UI suites share `SyntheticScreen`.
All 11 existing methods remain, including the opt-in real-fingerprint method.
The same ten noninteractive runs passed before and after consolidation on the
isolated API 36 emulator; all eight JVM tests, test-APK packaging and lint also
passed. A baseline System UI ANR was dismissed before completing the comparison;
the failed-save error assertion was retained. Android has no configured numerical
coverage gate, so no line/branch coverage comparison is claimed. Production code
and the installed phone APK were unchanged by this test maintenance.

## Remaining device acceptance sequence

1. Install a privately signed release APK, then upgrade it with the same key;
   confirm the encrypted vault and biometric enrollment remain usable.
2. Download a synthetic synced vault, unlock by password and by external key,
   enable biometrics, kill/reopen the app, and unlock again without the key file.
3. Cancel/fail biometric prompts; enroll another fingerprint and confirm fallback
   to the original credential. Change the vault password elsewhere and confirm
   stale biometric material is rejected. Disable biometric unlock and retest.
4. Fill and save a test login in Chrome, including separate username/password
   pages and same/cross-origin frames. HTTP, ambiguous origins, and untrusted
   browser signers must never receive a credential. Test another supported browser.
5. Register/sign in with a passkey at an HTTPS relying party using a test account.
   Verify explicit consent, excluded credentials, no matching credential, request
   cancellation, process restart, and offline use of an existing passkey.
6. Exercise native app password binding and native passkey Digital Asset Links;
   verify an unrelated app/certificate cannot request another app's credentials.
7. Edit on two devices offline, reconnect, review conflicting fields, and verify
   both encrypted recovery copies. Confirm synced passkeys work on another Android
   device with the same vault, without copying an unencrypted private key.
8. Background the app or turn off the screen while viewing a secret, during an
   unlock, and during sync. Verify the UI clears, late callbacks stay invalid, and
   authentication is required on return. Check the five-minute idle timeout.
9. Export/import an encrypted vault, restore its passkeys/history/trash, and check
   that screenshots, Android backups, and device transfer cannot capture app data.
10. With a synthetic multi-step login, check the locked **Unlock** suggestion,
    automatic fingerprint prompt and cancellation fallback, compact account sheet,
    then direct account suggestions on the password and TOTP steps without another
    unlock. Check a keyboard with inline support and one using dropdown fallback,
    overflow via **More accounts**, visible custom ports, and stale/removed account
    recovery. Screen-off, another site, and an expired grant must require unlock.
