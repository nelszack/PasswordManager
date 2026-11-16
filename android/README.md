# Private Android application

The Android client embeds `pm-mobile` and calls the existing Rust vault library
in process. It does not connect to the desktop's local socket. Password autofill
requires 64-bit Android 9+, and the password/passkey credential provider requires Android
14+. No Google Play services dependency or store publication is required.

## Build

Install JDK 21, Gradle 8.13, Rust, CMake, the Android SDK platform 36, build tools
35.0.0 and 36.0.0, platform-tools, and NDK 28.2.13676358. Set `JAVA_HOME`,
`ANDROID_HOME`, and optionally `ANDROID_NDK_HOME` and `GRADLE`. Add CMake to PATH.

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
installation from that source. Android developer-verification restrictions vary
by region; ADB remains the development installation path.

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

Enable Password Manager in the Android autofill/provider settings using the app's
buttons. Chrome also has an autofill provider preference; choose other providers
there if Chrome continues using Google Password Manager. No AccessibilityService
is used. Browser origins are accepted only for release-signed packages in the
bundled Google privileged-browser allowlist. Native app logins bind to package
and certificate; passkeys additionally require an HTTPS Digital Asset Link.

Android's legacy Autofill structure reports scheme and hostname but omits the
port. To preserve the desktop's origin policy, website password autofill also
requires a native browser address-bar value matching that hostname; the full
address supplies the port. HTML-supplied addresses are never accepted. If a
browser does not expose its native address bar, the legacy service refuses to
fill rather than silently match credentials across ports. Actual Chrome/Firefox
compatibility must be checked on the phone. Credential Manager's delegated
origin API used by passkeys/password-provider requests does include a full
origin and does not require this legacy fallback.

The initial phone interface displays TOTP codes. HOTP advancement, Duo management,
and the remaining desktop tools are tracked as later mobile parity work. Their
encrypted vault data is preserved.

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

Import Google CSV on the desktop with an import preview, review Samsung Pass for
unique items, and sync the resulting vault. Direct Google credential exchange
requires separate implementation; do not assume Google's passkeys were included
in a CSV export.

## Verification

See [the acceptance checklist](../docs/mobile-implementation.md). A successful APK
build is distinct from physical-phone verification of autofill, biometric
invalidation, HTTPS passkeys, and installation/upgrades.

The JNI integration tests create and remove synthetic vaults. Run them only on
an isolated emulator after building the app. Set `ANDROID_SERIAL` to that emulator:

```sh
gradle -p android :app:assembleDebugAndroidTest
adb -s "$ANDROID_SERIAL" install -r android/app/build/outputs/apk/debug/app-debug.apk
adb -s "$ANDROID_SERIAL" install -r android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s "$ANDROID_SERIAL" shell am instrument -w \
  dev.nelszack.passwordmanager.test/androidx.test.runner.AndroidJUnitRunner
```

These tests verify the packaged Rust library, encrypted persistence, cached-key
unlock policy, Android manifest protections, and WebAuthn signatures independently
using Android's crypto implementation. They do not simulate a fingerprint sensor
or prove real-browser autofill behavior.

The browser signer list in `app/src/main/assets/trusted-browsers.json` is a snapshot
of Google's publicly documented
[privileged app allowlist](https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json).
Only release fingerprints are trusted. Updating that list is a reviewed source change.
