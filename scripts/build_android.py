#!/usr/bin/env python3
"""Build Rust JNI libraries then a private APK; never download tools or keys."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
TARGETS = {
    "arm64-v8a": ("aarch64-linux-android", "aarch64-linux-android28-clang"),
    "x86_64": ("x86_64-linux-android", "x86_64-linux-android28-clang"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--abi", choices=TARGETS, action="append")
    parser.add_argument("--install", action="store_true", help="install/update on the connected ADB device")
    args = parser.parse_args()
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk:
        parser.error("Set ANDROID_HOME to your Android SDK")
    ndk = Path(os.environ.get("ANDROID_NDK_HOME", str(Path(sdk) / "ndk" / "28.2.13676358")))
    host = {"linux": "linux-x86_64", "darwin": "darwin-x86_64"}.get(sys.platform)
    if not host:
        parser.error("Use Linux or macOS for the Android build")
    tools = ndk / "toolchains" / "llvm" / "prebuilt" / host / "bin"
    if args.release:
        missing = [key for key in ("PM_ANDROID_KEYSTORE", "PM_ANDROID_STORE_PASSWORD", "PM_ANDROID_KEY_ALIAS", "PM_ANDROID_KEY_PASSWORD") if not os.environ.get(key)]
        if missing:
            parser.error("Release signing requires: " + ", ".join(missing))
    abis = args.abi or list(TARGETS)
    # Package only libraries built by this invocation, never stale ABIs.
    destination = ROOT / "android/app/src/main/jniLibs"
    if destination.exists():
        shutil.rmtree(destination)
    for abi in abis:
        target, compiler = TARGETS[abi]
        if not (tools / compiler).is_file():
            parser.error(f"Missing NDK compiler: {tools / compiler}")
        env = os.environ.copy()
        slug = target.replace("-", "_")
        env[f"CARGO_TARGET_{slug.upper()}_LINKER"] = str(tools / compiler)
        env[f"CC_{slug}"] = str(tools / compiler)
        env[f"AR_{slug}"] = str(tools / "llvm-ar")
        env["ANDROID_NDK_HOME"] = str(ndk)
        env["RUSTFLAGS"] = env.get("RUSTFLAGS", "") + " -C link-arg=-Wl,-z,max-page-size=16384"
        command = ["cargo", "build", "--locked", "-p", "pm-mobile", "--target", target]
        if args.release:
            command.append("--release")
        subprocess.run(command, cwd=ROOT, env=env, check=True)
        output = Path(env.get("CARGO_TARGET_DIR", str(ROOT / "target")))
        if not output.is_absolute():
            output = ROOT / output
        library = output / target / ("release" if args.release else "debug") / "libpm_mobile.so"
        (destination / abi).mkdir(parents=True, exist_ok=True)
        shutil.copy2(library, destination / abi / library.name)
        subprocess.run([str(tools / "llvm-strip"), "--strip-debug", str(destination / abi / library.name)], check=True)
    gradle = os.environ.get("GRADLE") or shutil.which("gradle")
    if not gradle:
        parser.error("Install Gradle 8.13 or set GRADLE to its executable")
    mode = "release" if args.release else "debug"
    subprocess.run([gradle, "--console=plain", "-PpmAbis=" + ",".join(abis), ":app:assemble" + mode.capitalize(), ":app:testDebugUnitTest", ":app:lintDebug"], cwd=ROOT / "android", check=True)
    apk = ROOT / f"android/app/build/outputs/apk/{mode}/app-{mode}.apk"
    print(f"APK: {apk}")
    if args.install:
        adb = str(Path(sdk) / "platform-tools/adb")
        subprocess.run([adb, "install", "-r", str(apk)], check=True)


if __name__ == "__main__":
    main()
