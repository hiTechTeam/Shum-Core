#!/usr/bin/env python3
"""Inspect an installer without installing it or changing an existing profile."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET


package = Path(sys.argv[1]).resolve(strict=True)
manifest = json.loads(package.with_suffix(".json").read_text())
assert hashlib.sha256(package.read_bytes()).hexdigest() == manifest["sha256"]
with tempfile.TemporaryDirectory(prefix="shum-package-check-") as temporary:
    unpacked = Path(temporary) / "expanded"
    subprocess.run(["/usr/sbin/pkgutil", "--expand-full", str(package), str(unpacked)], check=True)
    payload = unpacked / "Shum-cli.pkg/Payload"
    assert sorted(str(p.relative_to(payload)) for p in payload.rglob("*") if p.is_file()) == [
        "usr/local/bin/shum"
    ]
    binary = payload / "usr/local/bin/shum"
    assert os.access(binary, os.X_OK)
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == manifest["binarySha256"]
    receipt = ET.parse(unpacked / "Shum-cli.pkg/PackageInfo").getroot()
    assert receipt.attrib["identifier"] == "org.shum.cli"
    assert receipt.attrib["install-location"] == "/"
    assert receipt.attrib["version"] == manifest["version"]
    distribution = ET.parse(unpacked / "Distribution").getroot()
    assert distribution.find("volume-check/allowed-os-versions/os-version").attrib["min"] == manifest["minimumMacOS"]
    assert distribution.find("options").attrib["hostArchitectures"] == manifest["architecture"]
    assert distribution.find("domains").attrib["enable_currentUserHome"] == "false"
    environment = dict(os.environ, PATH="/usr/bin:/bin:/usr/sbin:/sbin")
    result = subprocess.run([str(binary), "--version"], env=environment,
                            check=True, capture_output=True, text=True)
    assert result.stdout.strip() == f'shum {manifest["version"]}'
    result = subprocess.run([str(binary), "--help"], env=environment,
                            check=True, capture_output=True, text=True)
    assert "chats" in result.stdout and "profile" in result.stdout
    archive = package.parent / f'shum-{manifest["version"]}-macos-{manifest["architecture"]}.tar.gz'
    with tarfile.open(archive) as bundle:
        assert bundle.getnames() == ["shum"]
        assert hashlib.sha256(bundle.extractfile("shum").read()).hexdigest() == manifest["binarySha256"]
    formula = (package.parent / "homebrew-shum/Formula/shum.rb").read_text()
    assert hashlib.sha256(archive.read_bytes()).hexdigest() in formula
    assert 'bin.install "shum"' in formula
print("PASS: payload, receipt, OS/CPU requirements, archive and checksums")
print("PASS: CLI --version and --help with only system executables in PATH")
print("Installer was inspected, not installed. Existing profiles were not accessed.")
