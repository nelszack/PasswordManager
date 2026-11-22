# Private Android application

The Android client embeds `pm-mobile` and calls the existing Rust vault library
in process. It does not connect to the desktop's local socket. Password, card, and
identity autofill requires 64-bit Android 9+, and the password/passkey credential provider requires Android
14+. No Google Play services dependency or store publication is required.

Current development build: **0.3.0 (version code 12)**. It has been tested with
synthetic data on a physical Android 13 phone and an Android 16 emulator; Android
14+ passkey-provider operation has not yet been verified on hardware. See the
[verification record and outstanding acceptance checks](../docs/mobile-implementation.md)
and the [daily-use guide](../docs/user-guide.md#android-app).

## Build

Install JDK 21, Gradle 8.13, Rust, CMake, the Android SDK platform 36, build tools
35.0.0 and 36.0.0, platform-tools, and NDK 28.2.13676358. Set `JAVA_HOME`,
`ANDROID_HOME`, and optionally `ANDROID_NDK_HOME` and `GRADLE`. Add CMake to PATH.
The build helper supports Linux and macOS. Windows can install the resulting APK
using ADB; the helper does not build Android JNI libraries on Windows.

```sh
rustup target add aarch64-linux-android x86_64-linux-android
python3 scripts/build_android.py
```

The result is `android/app/build/outputs/apk/debug/app-debug.apk`. For one physical
ARM64 phone, use `--abi arm64-v8a`. The script builds JNI libraries first, then
assembles the APK and runs Android unit tests and lint. Signing-key environment
values are consumed by Gradle and never passed as command-line arguments.

## Install and update

Enable developer options and USB debugging on your phone, connect it, and approve
your computer's debugging key. Then:

```sh
adb devices
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

`python3 scripts/build_android.py --install` combines the steps. The phone's
package installer can also open a downloaded/copied APK after you enable
installation from that source. USB/ADB is the verified development installation
path for this project.

### Wireless updates (no cable)

Android 11+ supports wireless debugging. The phone must be on Wi-Fi (Android
disables wireless debugging on mobile data) and reachable from the computer:
either on the same local network, or connected to a VPN or mesh network (such as
Tailscale or WireGuard) that the computer can also reach. If you use a VPN app,
keep it connected while updating, for example by disabling battery optimization
for it or enabling it as the *Always-on VPN*.

Pair once. On the phone, open *Developer options → Wireless debugging → Pair
device with pairing code*, then run:

```sh
"$ANDROID_HOME/platform-tools/adb" pair <phone-ip>:<pairing-port> <code>
```

To update, turn Wireless debugging on and run one of:

```sh
python3 scripts/build_android.py --abi arm64-v8a --device <phone-ip>  # build, then install
python3 scripts/build_android.py --install-only --device <phone-ip>   # reinstall the last build
```

The script asks for the port shown on the phone's Wireless debugging screen
(it changes every time the setting is toggled; pass `HOST:PORT` to skip the
prompt). Setting `PM_ANDROID_DEVICE` to the phone's address lets `--install` and
`--install-only` use it by default. Wireless debugging gives full device
control to any paired computer, so turn it off after updating.

Update by installing a higher-version APK with the same package identity and
signing key. Do not uninstall to update: uninstalling removes the local vault and
device keys. Export an encrypted vault or verify sync before changing signing keys.

For long-term personal use, generate and back up a dedicated release signing key
outside this repository. Keep its passwords in your existing password manager.

```sh
keytool -genkeypair -keystore /absolute/private/path/pm-android.jks \
  -alias password-manager -keyalg RSA -keysize 3072 -validity 10000
```

Set `PM_ANDROID_KEYSTORE`, `PM_ANDROID_STORE_PASSWORD`, `PM_ANDROID_KEY_ALIAS`, and
`PM_ANDROID_KEY_PASSWORD` in your local environment, then run:

```sh
python3 scripts/build_android.py --release --abi arm64-v8a
```

The debug and release signatures differ. Use release signing from your first
long-term installation. Never commit or upload signing keys or their passwords.

## Setup

Download an existing vault using its HTTPS sync server and a distinct device token,
or import an encrypted `.enc` vault using the system file picker. For key-file
vaults, choose the external key file on unlock; its contents are passed transiently
to Rust and are not saved. Create a new vault if needed.

After unlocking with the original credential, explicitly enable biometric unlock.
The app protects a saved vault key using an authentication-per-use Android Keystore
key; each unwrap uses BiometricPrompt with a CryptoObject and strong biometrics.
Enrollment changes invalidate the protected key. Use the original password/key
after invalidation, a vault password change, or moving to another phone.
The authenticated cipher processes AAD and vault material only after the
CryptoObject succeeds. Provider errors are displayed instead of escaping a
callback; backgrounding cancels pending authentication and clears setup material.
The home, Settings, and unlock screens show whether biometric unlock is enabled
for the selected vault on this device. **Settings → Biometric unlock** shows the
matching enable/disable action. The unlock button is disabled for vaults
that have no biometric enrollment, and updates when the vault selection changes.

Enable Password Manager in the Android autofill/provider settings using the app's
buttons. Chrome also has an autofill provider preference; choose other providers
there if Chrome continues using Google Password Manager. No AccessibilityService
is used. Browser origins are accepted only for release-signed packages in the
bundled Google privileged-browser allowlist. Native app logins bind to package
and certificate; passkeys additionally require an HTTPS Digital Asset Link.

Android's legacy Autofill structure reports scheme and hostname but omits the
port. A matching native browser address bar supplies an exact origin when
available. HTML-supplied addresses are never accepted, and conflicting native
addresses are rejected. In release-signed Chrome, missing address-bar metadata
uses the user-approved exact-hostname picker: unlock (or reuse a valid completed
same-site autofill grant), then explicitly choose a login and its saved HTTPS
address. No choice is automatic, wildcard
and parent/sibling domains are excluded, and saved nonstandard ports are shown.
The current page's port cannot be verified in this mode. Secret retrieval still
validates the selected saved origin through Rust's existing exact-origin API;
desktop and Credential Manager origin rules are unchanged. Other browsers
without full native address evidence still refuse legacy filling. Saving in
hostname mode asks the user to check the saved address/port and prevents an
update from silently moving an existing login to another port. Invisible form
fields are ignored. Actual browser filling remains a separate hardware check.

Payment-card and identity forms (checkout, address, and contact forms) are offered
only when the screen has no login fields. Fields are classified by the Rust vault
library with the same rules as the browser extension, and the same caller checks
apply: native apps by package and certificate, browsers only through the trusted
allowlist. The person always unlocks if needed and picks the card or identity in
the fill sheet; no card or identity data reaches Android before that choice.
Dropdown fields are not filled. Real checkout and address forms remain a separate
hardware check. See the [user guide](../docs/user-guide.md#fingerprint-unlock-and-autofill)
for which fields are filled.

Autofill reuses a successful unlock for the same caller and site for up to five
minutes between completed fills, so username, password, and code steps do not
each require authentication. Each step still requires an explicit account
choice. Only a completed fill/copy handoff keeps the session: cancellation,
backgrounding before completion, opening vault management, explicit locking,
screen-off, expiration, or process restart ends it. Grants are kept only in
memory; different sites/callers require a new unlock. Passkey/provider requests
continue to require fresh authentication.

Verification-code fields with explicit hints (including Google's `totpPin`)
offer matching TOTP-enabled entries, including code-only entries. They use the
existing Rust generator, not a new enrollment. Codes must be associated with a
matching website address in the vault; issuer names alone never authorize
filling. HOTP counters are not consumed. The picker offers **Copy verification
code and return**, and item details provide **Copy username**, **Copy password**,
and **Copy verification code**. A code is generated afresh for each action.
Copied values are marked sensitive to suppress clipboard previews. A best-effort
ownership-checked timer clears them after the configured interval (30 seconds by
default, 1–300 seconds), sooner when a TOTP code expires. It never clears a newer
clipboard value. HOTP is available only through its explicit counter-consuming
management action, never through automatic filling.

## Vault management and recovery

Version 0.3.0 reorganizes the app around **Vault**, **Tools**, and **Settings**.
The vault has live search, horizontally scrollable item-type filters, and rows
showing the account and item type. Item details group secrets with explicit
show/hide and copy controls. Light and dark appearances follow Android.

Editing keeps **Cancel** and **Save item** above the keyboard, asks before
discarding a changed draft, and preserves inputs when saving fails. Management
screens have a consistent Back action and show progress for background work.
Results from screens you have left cannot replace the current screen.

**Tools & recovery**, introduced in 0.2.0 and available from the **Tools** tab,
includes:

- All eight item types, multiple websites, notes, ordinary/secret custom fields,
  revision-checked editing, and copy actions. Passkey private fields stay hidden
  from normal details and cannot be modified through the ordinary item editor.
- Password history with restore, encrypted trash with restore/confirmed purge,
  advanced search/filter/sort, and vault health reports. Breach checks are off by
  default and require opting into sending hash prefixes to the shared checker.
- Configurable password/passphrase generation and local strength assessment.
  The standalone generator also works from the locked home screen.
- Authenticator setup/change/removal for Base32 or otpauth input; HOTP generation
  requires confirmation and persists its counter. Use one device at a time for
  HOTP; counter conflicts still require explicit sync reconciliation.
- Duo activation and HOTP/TOTP selection. Pending push requests for every
  enrolled account appear on one screen (vault list → **Duo Push requests**),
  answered with one tap on the reviewed card, plus Verified Push input. Shared expiry/fingerprint validation
  applies. Do not retry a decision with an unknown outcome without checking the
  login. Live Duo enrollment/push acceptance requires a dedicated test account.
- Complete encrypted backup containers using a dedicated backup password or an
  existing key file. Restore creates a separate vault identity and preserves
  history, trash, authenticators and passkeys. Snapshot `.enc` import/export is
  also available. Mobile document transfers are limited to **16 MiB**.
- CSV/JSON imports with preview and duplicate policies. Applying an import checks
  the preview token, file digest, selected policy and unchanged local revision.
  Leaving/locking the session invalidates approval. Plaintext exports require
  explicit consent; JSON preserves richer metadata. CSV cannot preserve passkeys
  and is rejected for vaults containing them.

File destinations are picked before export contents are generated. Returning from
an external picker locks the vault and requires unlocking again for vault exports.
No plaintext staging files are written inside the app. Returning to the main
home screen from a management tool locks the vault. A cancelled picker does
not mutate the vault; an interrupted external write can leave a partial document
that must not be treated as a valid backup.

**External-key vault tools** on the home screen first saves a new random key file,
then asks you to choose that saved file to create a vault. **Vault credentials**
requires an original password/key-file unlock for rekeying or local vault deletion.
Rekeying preserves a private encrypted recovery snapshot before atomic replacement,
then locks the vault. Biometric enrollment is disabled and must be set up again.
Recovery/comparison copies require explicitly enabling sync before synchronizing;
old encrypted recovery copies still need their original credentials.

**Mobile settings** groups preferences and displays readable current values such
as **5 minutes** or **24 characters**. Tap a row for its units, default, valid
range and explanation; the edit dialog validates before saving and offers common
auto-lock presets. Cancel leaves the preference unchanged. It controls auto-lock (15 seconds–24 hours), clipboard expiry,
history limit, generator defaults and trash retention. Trash retention is applied
explicitly from Deleted items; zero disables age-based purging. Autofill grants
remain scoped to one caller/site and at most five minutes between completed fills,
and can end sooner when the configured vault timeout expires.

**Sync controls** shows local checkpoint state, checks the server without applying
changes, and enables/disables sync per vault. Cloud download also offers a separate
comparison copy with sync disabled. Use Review sync conflicts to resolve concurrent
changes; full two-device acceptance remains a separate test.

## Keyboard autofill interaction

On Android 11+, supported keyboards receive inline suggestions, with Android's
dropdown as fallback. A locked vault exposes only an **Unlock** chip. It opens
a secure, height-limited bottom sheet and automatically offers the selected
vault's configured biometrics; password/key-file fallback stays in the sheet.
After unlocking, account choice is explicit. During the same-site session,
named account chips fill directly on tap without reopening the account picker.
Large account lists include **More accounts**. Saved nonstandard ports appear
at the beginning of chip subtitles. Account metadata, vault selection, and the
site are revalidated after tapping; stale suggestions return to the chooser.
Suggestions contain authentication actions and null field values until tapped,
never passwords or verification codes. The keyboard ultimately decides whether
to render inline suggestions.

## Passkey behavior

New ES256 passkeys are discoverable and their private keys are encrypted inside
the existing vault as the reserved secret field `pm.passkey.v1`. This preserves
desktop-format compatibility, encrypted backups, portable JSON, and snapshot sync.
The app asks for a fresh vault unlock and explicit consent before credential use.
Normal item details omit the private passkey field. Deleting the item moves it to
encrypted trash using the existing vault policy.

The authenticator uses `none` attestation, zero counters for synchronized passkeys,
and UP/UV/BE flags (backup completion is not asserted). Hardware attestation, roaming/security-key operation,
cross-device QR authentication, PRF/largeBlob extensions, and related-origin
requests are not implemented. There is no claim of FIDO certification.

## Sync and recovery

Changes save locally first. The sync action uses the existing HTTPS protocol and
optimistic version checks. If both local and remote have changed, both encrypted
copies are preserved and a comparison `.enc` is saved beside the local vault;
the app does not silently choose a winner. Use **Review sync conflicts** to choose
local/cloud values per field, or use the desktop conflict review workflow. Reviews
are bound to the local revision and remote version; stale reviews are rejected.
Both original snapshots are saved before applying a merge. The server token is encrypted using a separate Android Keystore
key. Android backup/device-transfer of this app's files is disabled.

Saving a connection clears the credential field before testing the server. New
credentials are saved only after that test succeeds; paste the credential again
after a failed first connection. A blank field reuses a previously saved
credential. Connection errors include the underlying network/certificate cause.
The complete Rustls Android AAR is resolved at the companion version in
`Cargo.lock`, including its narrowly scoped HTTP permissions for CA-signed
certificate revocation lists. Vault sync itself still requires HTTPS. Stripping
the AAR to a JAR loses that policy and can produce misleading `Revoked` errors
for valid Let's Encrypt certificates; see
[upstream issue 221](https://github.com/rustls/rustls-platform-verifier/issues/221).

Import Google CSV on the desktop with an import preview, review any other password
manager you used (such as a phone vendor's) for unique items, and sync the resulting vault. Direct Google credential exchange
requires separate implementation; do not assume Google's passkeys were included
in a CSV export.

## Verification

See [the acceptance checklist](../docs/mobile-implementation.md). A successful APK
build is distinct from physical-phone verification of autofill, biometric
invalidation, HTTPS passkeys, and installation/upgrades.

The JNI integration tests create and remove synthetic vaults. Run them only on
an isolated emulator after building the app. Set `ANDROID_SERIAL` to that emulator:

If the JNI build selected one ABI, pass the same `-PpmAbis=...` to Gradle below;
the default expects both `arm64-v8a,x86_64`. Gradle does not rebuild Rust itself.

```sh
gradle -p android :app:assembleDebugAndroidTest
adb -s "$ANDROID_SERIAL" install -r android/app/build/outputs/apk/debug/app-debug.apk
adb -s "$ANDROID_SERIAL" install -r android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s "$ANDROID_SERIAL" shell am instrument -w \
  -e class dev.nelszack.passwordmanager.MobileIntegrationTest \
  dev.nelszack.passwordmanager.test/androidx.test.runner.AndroidJUnitRunner
```

These tests verify the packaged Rust library, encrypted persistence, cached-key
unlock policy, Android manifest protections, and WebAuthn signatures independently
using Android's crypto implementation. They do not simulate a fingerprint sensor
or prove real-browser autofill behavior.

To diagnose HTTPS connectivity on a connected device without opening its vaults
or saved credential, build/install the test APK and run only the opt-in transport
test. It uses an isolated cache directory and a dummy token; success means the
server returned the expected unauthorized response through the app's Rust stack.

```sh
adb shell am instrument -w \
  -e class dev.nelszack.passwordmanager.SyncConnectivityTest \
  -e syncServer https://YOUR-SERVER:8443 \
  dev.nelszack.passwordmanager.test/androidx.test.runner.AndroidJUnitRunner
```

Run `BiometricUnlockTest` alone in a fresh instrumentation process to check
callback errors, cancellation of stale callbacks, and clearing rejected setup
material. It primes Rust storage into a temporary cache directory and never
opens personal vaults. Add `-e interactiveBiometrics true` and keep the phone
unlocked to exercise enrollment and unlock with two real fingerprint prompts
against a synthetic vault. The test removes only its temporary biometric key.

```sh
adb shell am instrument -w \
  -e class dev.nelszack.passwordmanager.BiometricUnlockTest \
  -e interactiveBiometrics true \
  dev.nelszack.passwordmanager.test/androidx.test.runner.AndroidJUnitRunner
```

`AutofillHostnameTest` also runs alone in a fresh process with isolated cache
storage. It verifies the packaged Rust hostname picker exposes no passwords,
rejects lookalike hosts and locked requests, and preserves exact-port secret
checks after a saved address is selected:

```sh
adb shell am instrument -w \
  -e class dev.nelszack.passwordmanager.AutofillHostnameTest \
  dev.nelszack.passwordmanager.test/androidx.test.runner.AndroidJUnitRunner
```

`AutofillSessionLifecycleTest` runs alone against a synthetic cache-only vault
and a non-exported debug fixture activity. It verifies that a completed handoff
retains the native unlock, while cancellation, opening management, and explicit
lock revoke it. JVM tests cover caller/site isolation, expiry, and verification
field recognition. No fingerprint or personal vault is needed for these tests.

Run `AutofillPresentationTest` and `AutofillDirectFillTest` separately, each in
a fresh instrumentation process with the phone unlocked. The first checks inline
style negotiation and the secure sheet's size. The second opens a test-only
synthetic login form in the test APK and taps a named suggestion through Android's
autofill framework, checking that it fills without another picker. Both bind Rust
to temporary cache storage before launching UI. They do not exercise a personal
vault or prove that a particular browser/keyboard renders inline suggestions.
Do not run these isolated classes together: the JNI storage path is cached for
the lifetime of the process. After testing, force-stop the main app and remove
only `dev.nelszack.passwordmanager.test`; reopening the main app then restores its
normal private storage path. Never clear the main app's data for these checks.

`MobileParityNativeTest` runs alone with JNI bound to a synthetic cache directory.
It covers typed metadata, history/trash, authenticators, backup/import/export,
key-file creation/rekey, privilege checks and passkey-data preservation on the
installed ABI. `MobileParityTest` separately drives native management screens and
uses a non-exported debug document provider plus an intercepted document picker.
It never browses user files, accesses personal vaults, changes stored connection
credentials or uploads fixture records. These tests do not replace actual system
picker, interactive biometric, Google MFA or live Duo provider acceptance.

`MobileRedesignTest` separately exercises the actual vault screens using a
cache-only synthetic vault and a debug-only activity that disables post-edit
sync. It checks search/type filters, secret visibility, settings cancellation,
draft protection and failed-save recovery. Run it alone in a fresh process like
the other isolated UI tests. Optional `uiTheme` (`light`/`dark`) and `uiScale`
arguments affect only the fixture activity. Screenshot capture (`captureUi true`)
is restricted to the isolated emulator; normal app and phone-test windows retain
their screenshot protection.

The cache-only hostname, parity, redesign, presentation, direct-fill, session and
biometric suites share `SyntheticVaultRule`. It binds JNI before any UI launch,
tracks activities, settles queued work, locks and deletes only its UUID cache
directory, including after partial test failure. It rejects a second isolated
class in the same process because JNI retains its first directory.
`SyntheticScreen` shares native widget lookup/navigation between the two
management UI suites; their behavior assertions remain in the individual tests.

The browser signer list in `app/src/main/assets/trusted-browsers.json` is a snapshot
of Google's publicly documented
[privileged app allowlist](https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json).
Only release fingerprints are trusted. Updating that list is a reviewed source change.
