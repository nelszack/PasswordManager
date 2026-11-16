# Mobile and passkey implementation checklist

This is the acceptance checklist for `feature/android-passkeys`. Checked boxes
mean software is implemented with source/build/test evidence recorded below.
They do not imply physical-phone acceptance: device checks remain separate from host tests. Never use a personal vault in tests.

Current delivery is an Android development APK. Release acceptance is incomplete
until the physical-phone checks below pass. In particular, legacy browser autofill
fails closed if the browser does not expose a verifiable full origin, including
its port; do not assume every browser is compatible before testing it.

## Agreed scope

Android first; iPhone later. A native vault app and website autofill are required.
There is no hosted web vault. Existing desktop vaults and the encrypted snapshot
sync server remain the source of interoperable vault data. Distribution is a
privately signed APK, installable by USB/ADB or Android's package installer.

## Shared vault and compatibility

- [x] A mobile API uses the existing Rust encryption, vault format, entry rules,
  generators, OTP implementation, and sync protocol without a desktop daemon.
- [x] Open existing password and external-key vaults; create password vaults.
- [x] List/search, reveal, create, edit, delete logins; inspect other item types.
- [x] Keep keys and secrets out of logs, debug formatting, and error messages.
- [x] Locked operations fail; lock drops decrypted entries and session keys.
- [x] Existing desktop clients preserve passkeys across edits, sync, and backups.
- [x] Portable exports preserve passkeys; lossy CSV exports explain omissions.
- [x] Regression tests use synthetic vaults and verify desktop/mobile compatibility.

## Android application and lifecycle

- [x] Native Android project packages the Rust library and has reproducible build instructions.
- [x] All vault files live in app-private storage; cloud backups and screenshots are disabled.
- [x] Unlock, vault selection, search, editing, generator, OTP and explicit lock UI.
- [x] Backgrounding, screen lock, and inactivity clear the unlocked session.
- [x] Long-running encryption and network operations run off the main thread.
- [x] Import an existing encrypted vault and external key through Android's file picker.
- [x] Export encrypted backups and inspect all imported item types without data loss.

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
- [x] Parse username/password fields including nested browser structures.
- [x] Require an explicit account choice and unlock before releasing credentials.
- [x] Match HTTPS websites using the existing origin policy; reject HTTP and ambiguous origins.
- [x] Trust browser-reported origins only from verified browser package certificates.
- [x] Preserve origin ports using a native browser address-bar value; fail closed
  when legacy Android Autofill supplies only a hostname. Never trust HTML URL attributes.
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
- [x] User verification and explicit consent precede every passkey operation.
- [x] Cancellation and excluded/unsupported credentials return the appropriate provider errors.
- [x] List and delete passkeys without exposing private key material in the normal interface.
- [x] Preserve passkeys on portable JSON import/export; warn about unsupported external passkey formats.
- [ ] Test registration and sign-in with a real HTTPS relying party on Android.

## Sync and migration

- [x] Configure HTTPS sync endpoint and a per-device credential stored encrypted by Android Keystore.
- [x] List/download existing cloud vaults and check their encrypted identity before accepting them.
- [x] Synchronize unlocked changes with optimistic concurrency; preserve both sides on conflicts.
- [x] Retry safely after offline operation or uncertain upload acknowledgement.
- [x] Provide conflict review/recovery without silently overwriting either copy.
- [x] Google CSV import uses the existing preview and conflict policies; document Samsung Pass review.

## Private distribution

- [x] Provide debug/release APK build paths, with release signing supplied by the owner.
- [x] No production signing keys, vaults, or device tokens are committed.
- [x] Document ADB installation/update, same-key upgrades, signing-key backup, and Android verification constraints.
- [x] Successful host Rust tests and Android compile/package check recorded below.
- [ ] Install and upgrade on a physical phone, preserving the encrypted local vault.

## Later interoperability work (not implemented by the initial Android adapter)

- [ ] Desktop browser passkey creation/sign-in integration and its security tests.
- [ ] Android Credential Exchange import/export for direct Google and other provider transfers.
- [ ] External passkey import formats, including supported Bitwarden/FIDO CXF key representations.
- [ ] PRF/largeBlob extensions, related-origin requests, and cross-device QR authentication.
- [ ] Mobile payment-card and identity autofill.
- [ ] Mobile HOTP advancement and Duo enrollment/push management.
- [ ] Mobile history, trash/restore, audit, and backup-container restore interfaces.
- [ ] Mobile CSV/JSON import previews and conflict policies (desktop versions remain usable).
- [ ] Mobile external-key vault creation, credential changes/rekeying, and non-login item editing.

## Later iPhone phase (not part of the Android release)

- [ ] Swift interface and generated/native bridge to the same Rust mobile API.
- [ ] Keychain biometric key protection with Face ID/Touch ID enrollment invalidation.
- [ ] Password AutoFill credential provider extension, including passkeys.
- [ ] App/extension sharing, locking and encrypted sync verified on hardware.
- [ ] Private signed installation and provisioning renewal instructions; no App Store publication.

## Verification evidence

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
