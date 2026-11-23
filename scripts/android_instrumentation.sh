#!/usr/bin/env bash
# Run every unattended instrumentation class on an isolated emulator, each in its
# own instrumentation process (the JNI adapter keeps its first storage directory
# for the process lifetime), and collect MobileRedesignTest screenshots.
#
#   scripts/android_instrumentation.sh APK_DIR [OUT_DIR]
#
# APK_DIR holds app-debug.apk and app-debug-androidTest.apk from the same build.
# Refuses to run on anything but an emulator: these tests create and delete
# vaults in the app's normal storage and change the autofill provider.
set -uo pipefail

apks="${1:?usage: $0 APK_DIR [OUT_DIR]}"
out="${2:-android-instrumentation}"
app=dev.nelszack.passwordmanager
runner="$app.test/androidx.test.runner.AndroidJUnitRunner"
adb=(adb)
[[ -n "${ANDROID_SERIAL:-}" ]] && adb+=(-s "$ANDROID_SERIAL")

hardware="$("${adb[@]}" shell getprop ro.hardware | tr -d '\r')"
if [[ "$hardware" != ranchu && "$hardware" != goldfish ]]; then
    echo "Refusing to run: the device is not an emulator (ro.hardware=$hardware)." >&2
    exit 2
fi

mkdir -p "$out/screens"
"${adb[@]}" install -r "$apks/app-debug.apk" >/dev/null
"${adb[@]}" install -r "$apks/app-debug-androidTest.apk" >/dev/null
# The autofill tests fill a synthetic form through this app's service.
"${adb[@]}" shell settings put secure autofill_service "$app/$app.VaultAutofillService"

failed=()
run() {
    local name="$1"
    shift
    "${adb[@]}" shell am force-stop "$app"
    echo "=== $name"
    "${adb[@]}" shell am instrument -w "$@" "$runner" | tr -d '\r' >"$out/$name.txt"
    tail -n 3 "$out/$name.txt"
    if ! grep -q '^OK (' "$out/$name.txt"; then
        failed+=("$name")
    fi
}

run MobileIntegrationTest -e class "$app.MobileIntegrationTest"
run MobileParityNativeTest -e class "$app.MobileParityNativeTest"
run MobileParityTest -e class "$app.MobileParityTest"
run AutofillHostnameTest -e class "$app.AutofillHostnameTest"
run AutofillSessionLifecycleTest -e class "$app.AutofillSessionLifecycleTest"
run AutofillPresentationTest -e class "$app.AutofillPresentationTest"
run AutofillDirectFillTest -e class "$app.AutofillDirectFillTest"
# The interactive fingerprint test skips itself without its opt-in argument.
run BiometricUnlockTest -e class "$app.BiometricUnlockTest"
for theme in light dark; do
    run "MobileRedesignTest-$theme" -e class "$app.MobileRedesignTest" -e captureUi true -e uiTheme "$theme"
done

# Screenshots land in the debuggable app's cache; synthetic records only.
for file in $("${adb[@]}" shell run-as "$app" ls cache | tr -d '\r' | grep '^redesign-.*\.png$'); do
    "${adb[@]}" exec-out run-as "$app" cat "cache/$file" >"$out/screens/$file"
done
echo "Screenshots: $(find "$out/screens" -name '*.png' | wc -l) in $out/screens"

if ((${#failed[@]})); then
    echo "Failed: ${failed[*]}" >&2
    exit 1
fi
echo "All instrumentation classes passed."
