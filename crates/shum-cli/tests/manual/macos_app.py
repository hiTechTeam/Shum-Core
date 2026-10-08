#!/usr/bin/env python3
"""Check the macOS application launch path with disposable, offline profiles."""
import concurrent.futures
import json
import pathlib
import plistlib
import subprocess
import sys
import tempfile

assert sys.platform == "darwin"
binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="shum-app-test-") as directory:
    root = pathlib.Path(directory) / "profiles with spaces"

    def cli(*args):
        result = subprocess.run(
            [str(binary), "--data-dir", str(root), "--json", *args],
            capture_output=True, text=True, timeout=40,
        )
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        return json.loads(result.stdout)

    profiles = []
    try:
        for name in ["App launch A", "App launch B"]:
            created = cli("--relay", "ws://127.0.0.1:9", "--push-url", "off",
                          "init", "--headless", "--name", name)
            profiles.append(created["profile"]["id"])
        # Exercise concurrent bundle preparation and multiple app instances.
        with concurrent.futures.ThreadPoolExecutor() as pool:
            list(pool.map(lambda p: cli("-p", p, "status"), profiles))
        bundles = list(root.glob("services/*/Shum.app"))
        assert len(bundles) == 1, bundles
        bundle = bundles[0]
        info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
        assert info["CFBundleIdentifier"] == "org.shum.cli"
        assert info["NSBluetoothAlwaysUsageDescription"]
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(bundle)], check=True)
        pids = []
        for profile in profiles:
            endpoint = root / profile / "daemon.json"
            pid = json.loads(endpoint.read_text())["pid"]
            process = subprocess.check_output(["ps", "-p", str(pid), "-o", "comm="], text=True).strip()
            assert pathlib.Path(process).resolve() == (bundle / "Contents/MacOS/shum").resolve(), process
            assert endpoint.stat().st_mode & 0o777 == 0o600
            pids.append(pid)
        assert len(set(pids)) == 2
        print("PASS concurrent app launch, isolated profiles, signature, private IPC")
        for profile, old_pid in zip(profiles, pids):
            cli("-p", profile, "daemon", "--stop")
            assert not (root / profile / "daemon.json").exists()
            cli("-p", profile, "status")
            assert json.loads((root / profile / "daemon.json").read_text())["pid"] != old_pid
        assert list(root.glob("services/*/Shum.app")) == bundles
        print("PASS clean stop, restart and reuse of the signed bundle")
    finally:
        for profile in profiles:
            cli("-p", profile, "daemon", "--stop")
