#!/usr/bin/env python3
"""Exercise two isolated pm processes against the actual Go sync server.

Run after `cargo build --locked`: python3 scripts/test_cloud_sync.py
Only temporary test profiles, generated test credentials, and loopback ports are used.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(predicate, description):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError(f"Timed out: {description}")


class Device:
    def __init__(self, binary, root):
        self.binary, self.root, self.port = binary, root, free_port()
        self.env = dict(os.environ, PM_CONFIG_DIR=str(root / "config"), PM_DATA_DIR=str(root / "data"))
        self.env.pop("COMPLETE", None)
        self.log = open(root / "server.log", "w+")
        self.process = subprocess.Popen([binary, "--port", str(self.port), "run"], env=self.env,
                                        stdout=self.log, stderr=self.log)
        wait_for(lambda: self.run("status", ok=None).returncode == 0, "local server startup")

    def run(self, *args, ok=True):
        result = subprocess.run([self.binary, "--port", str(self.port), *args], env=self.env,
                                capture_output=True, text=True, timeout=125)
        if ok is not None:
            assert (result.returncode == 0) == ok, (args, result.stdout, result.stderr)
        return result

    def names(self):
        result = self.run("--json", "view")
        return json.loads(result.stdout)["data"]

    def set_automatic(self, enabled):
        path = self.root / "config" / "config.toml"
        text = path.read_text()
        text = text.replace("automatic = true", f"automatic = {str(enabled).lower()}") if not enabled else text.replace("automatic = false", "automatic = true")
        path.write_text(text)

    def close(self):
        with contextlib.suppress(Exception):
            self.run("kill", ok=None)
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pm", type=Path, default=ROOT / "target" / "debug" / "pm")
    args = parser.parse_args()
    binary = str(args.pm.resolve())
    with tempfile.TemporaryDirectory(prefix="pm-sync-test-") as temporary:
        root = Path(temporary)
        server_binary = root / "pm-sync"
        subprocess.run(["go", "build", "-o", str(server_binary), "."], cwd=ROOT / "sync-server", check=True)
        remote_home = root / "remote"
        storage = remote_home / ".local" / "share" / "pm-sync"
        token = root / "device-token"
        # Enrollment output contains a revocation ID, not the secret token itself.
        subprocess.run([str(server_binary), "--data", str(storage), "--add-device", "test",
                        "--credential-file", str(token)], check=True, capture_output=True)
        cloud_port = free_port()
        url = f"http://127.0.0.1:{cloud_port}"
        server_log = open(root / "cloud.log", "w+")
        cloud = subprocess.Popen([str(server_binary), "--data", str(storage), "--listen",
                                  f"127.0.0.1:{cloud_port}"], stdout=server_log, stderr=server_log)
        devices = []
        try:
            def reachable():
                try:
                    urllib.request.urlopen(url + "/v1/vaults", timeout=1)
                except urllib.error.HTTPError as error:
                    return error.code == 401
                except (OSError, urllib.error.URLError):
                    return False
                return False
            wait_for(reachable, "cloud server startup")
            for name in ("laptop", "desktop"):
                profile = root / name
                profile.mkdir()
                devices.append(Device(binary, profile))
            laptop, desktop = devices
            version = json.loads(subprocess.run([str(server_binary), "--version"], check=True, capture_output=True, text=True).stdout)
            assert version["protocol"] == 1
            subprocess.run([str(server_binary), "--health-check", url], check=True, capture_output=True)
            laptop.run("sync", "connect", url, "--token-file", str(token))
            desktop.run("sync", "connect", url, "--token-file", str(token))
            local_token = desktop.root / "config" / "sync-token"
            old_config = (desktop.root / "config" / "config.toml").read_bytes()
            old_token = local_token.read_bytes()
            invalid_token = root / "invalid-token"
            invalid_token.write_text("f" * 64 + "\n")
            for destination, credential in [(url, invalid_token), (f"http://127.0.0.1:{free_port()}", token)]:
                desktop.run("sync", "connect", destination, "--token-file", str(credential), ok=False)
                assert (desktop.root / "config" / "config.toml").read_bytes() == old_config
                assert local_token.read_bytes() == old_token
            print("PASS: manual connection failures preserve configuration and credentials")
            key = root / "external-test.key"
            laptop.run("new", "--key", str(key))
            laptop.run("unlock", "--key", str(key))
            laptop.run("add", "--name", "Initial", "--generate-password", "--no-copy")
            laptop.run("sync", "enable")
            remote_id = json.loads(laptop.run("sync", "vaults").stdout)[0]["id"]
            desktop.run("sync", "pull")
            desktop.run("unlock", "--key", str(key))
            assert "Initial" in str(desktop.names())
            print("PASS: new-device download and authenticated unlock")

            laptop.run("update", "--id", "1", "--name", "Automatic remote edit")
            wait_for(lambda: "Automatic remote edit" in str(desktop.names()), "automatic upload and notification download")
            print("PASS: automatic synchronization between independent local servers")

            # Stop automatic transfers so both devices edit the same remote base.
            for device in devices:
                device.set_automatic(False)
            time.sleep(2.2)
            laptop.run("update", "--id", "1", "--name", "Laptop conflict")
            desktop.run("update", "--id", "1", "--name", "Desktop conflict")
            laptop.run("sync", "now")
            conflict = desktop.run("sync", "now", ok=False)
            assert "conflict" in conflict.stderr.lower()
            assert "Desktop conflict" in str(desktop.names())
            assert "Laptop conflict" in str(laptop.names())
            desktop.run("sync", "pull", remote_id, ok=False)
            desktop.run("sync", "pull", remote_id, "--copy")
            assert len(list((desktop.root / "data").glob("*.enc"))) == 2
            checkpoints = [json.loads(p.read_text()) for p in (desktop.root / "data").glob("*.sync.json")]
            assert sorted(s["enabled"] for s in checkpoints) == [False, True]
            print("PASS: concurrent edits preserve both copies and allow a disabled comparison download")

            # Server persistence must survive a restart without changing the version.
            before = json.loads(laptop.run("sync", "vaults").stdout)
            cloud.terminate()
            cloud.wait(timeout=10)
            cloud = subprocess.Popen([str(server_binary), "--data", str(storage), "--listen",
                                      f"127.0.0.1:{cloud_port}"], stdout=server_log, stderr=server_log)
            wait_for(reachable, "cloud restart")
            assert json.loads(laptop.run("sync", "vaults").stdout) == before
            print("PASS: durable cloud versions survive server restart")
        finally:
            for device in devices:
                device.close()
            cloud.terminate()
            cloud.wait(timeout=10)
            server_log.close()


if __name__ == "__main__":
    main()
