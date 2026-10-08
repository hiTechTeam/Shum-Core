#!/usr/bin/env python3
"""Build a native macOS installer. End users do not need developer tools."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def macho_requirements(path):
    """Inspect the CLI and embedded BLE executable, including deployment targets."""
    data = path.read_bytes()
    images = []
    offset = 0
    while True:
        offset = data.find(b"\xcf\xfa\xed\xfe", offset)
        if offset < 0:
            break
        start = offset
        offset += 4
        if start + 32 > len(data):
            continue
        _, cpu, _, kind, count, size, _, _ = struct.unpack_from("<8I", data, start)
        if kind != 2 or cpu not in (0x100000C, 0x1000007) or not 0 < count < 4096:
            continue
        pos = start + 32
        end = pos + size
        if end > len(data):
            continue
        minimum = None
        dependencies = []
        for _ in range(count):
            if pos + 8 > end:
                break
            cmd, length = struct.unpack_from("<2I", data, pos)
            if length < 8 or pos + length > end:
                break
            if cmd == 0x32 and length >= 24:
                system, version = struct.unpack_from("<2I", data, pos + 8)
                if system == 1:
                    minimum = (version >> 16, (version >> 8) & 255, version & 255)
            elif cmd == 0x24 and length >= 16:
                version = struct.unpack_from("<I", data, pos + 8)[0]
                minimum = (version >> 16, (version >> 8) & 255, version & 255)
            elif cmd in (0xC, 0x80000018, 0x8000001F) and length >= 24:
                name_offset = struct.unpack_from("<I", data, pos + 8)[0]
                if 24 <= name_offset < length:
                    raw = data[pos + name_offset:pos + length].split(b"\0", 1)[0]
                    dependencies.append(raw.decode("utf-8"))
            pos += length
        else:
            if pos == end and minimum:
                images.append({"offset": start, "cpu": cpu, "minimum": minimum,
                               "dependencies": dependencies})
    if len(images) < 2 or images[0]["offset"] != 0:
        raise ValueError("Ожидался macOS CLI со встроенным BLE-бинарником")
    if len({image["cpu"] for image in images}) != 1:
        raise ValueError("Архитектуры CLI и встроенной службы не совпадают")
    for image in images:
        for dependency in image["dependencies"]:
            if not dependency.startswith(("/System/Library/", "/usr/lib/")):
                raise ValueError(f"Внешняя зависимость мешает автономной установке: {dependency}")
    architecture = "arm64" if images[0]["cpu"] == 0x100000C else "x86_64"
    minimum = max(image["minimum"] for image in images)
    return architecture, ".".join(map(str, minimum)), images


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="Упаковать уже проверенный бинарник")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--sign-installer", help="Имя сертификата Developer ID Installer")
    parser.add_argument("--release-base-url", help="HTTPS-каталог опубликованных артефактов")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("Установщик macOS собирается на macOS")
    if args.release_base_url:
        parsed = urlsplit(args.release_base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            parser.error("Для релиза нужен HTTPS URL каталога без query и fragment")
    version = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
                        (ROOT / "Cargo.toml").read_text(), re.M).group(1)
    source_revision = None
    if args.binary:
        binary = args.binary.expanduser().resolve(strict=True)
    else:
        env = dict(os.environ)
        env.setdefault("MACOSX_DEPLOYMENT_TARGET", "13.0")
        target = ROOT / "target" / "macos-package"
        run("cargo", "build", "--locked", "--release", "-p", "shum-cli",
            "--target-dir", str(target), cwd=ROOT, env=env)
        binary = target / "release" / "shum"
        source_revision = run("git", "describe", "--always", "--dirty", cwd=ROOT,
                              capture_output=True).stdout.strip()
    architecture, minimum, images = macho_requirements(binary)
    macos_names = {11: "big_sur", 12: "monterey", 13: "ventura", 14: "sonoma",
                   15: "sequoia", 26: "tahoe"}
    minimum_parts = tuple(map(int, minimum.split(".")))
    if minimum_parts[0] not in macos_names or minimum_parts[1:] != (0, 0):
        parser.error("Для формулы Homebrew нужен известный основной deployment target macOS")
    macos_name = macos_names[minimum_parts[0]]
    if architecture != platform.machine():
        parser.error("Этот скрипт проверяет и упаковывает только нативную архитектуру")
    clean_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"]}
    actual_version = run(str(binary), "--version", env=clean_env, capture_output=True).stdout.strip()
    if actual_version != f"shum {version}":
        parser.error(f"Версия бинарника {actual_version!r} не совпадает с {version}")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    suffix = "" if args.sign_installer else "-unsigned"
    package = output / f"Shum-CLI-{version}-macOS-{architecture}{suffix}.pkg"
    if package.exists():
        parser.error(f"Файл уже существует: {package}")
    with tempfile.TemporaryDirectory(prefix="shum-package-") as temporary:
        stage = Path(temporary)
        executable = stage / "root/usr/local/bin/shum"
        executable.parent.mkdir(parents=True)
        shutil.copy2(binary, executable)
        executable.chmod(0o755)
        component = stage / "Shum-cli.pkg"
        run("/usr/bin/pkgbuild", "--root", str(stage / "root"), "--identifier", "org.shum.cli",
            "--version", version, "--install-location", "/", "--ownership", "recommended",
            str(component))
        requirements = stage / "requirements.plist"
        requirements.write_bytes(plistlib.dumps({"arch": [architecture], "os": [minimum]}))
        distribution = stage / "Distribution.xml"
        run("/usr/bin/productbuild", "--synthesize", "--product", str(requirements),
            "--package", str(component), str(distribution))
        tree = ET.parse(distribution)
        document = tree.getroot()
        ET.SubElement(document, "title").text = "Shum CLI"
        ET.SubElement(document, "welcome", {"file": "welcome.html", "mime-type": "text/html"})
        ET.SubElement(document, "conclusion", {"file": "conclusion.html", "mime-type": "text/html"})
        ET.SubElement(document, "domains", {"enable_anywhere": "false",
                       "enable_currentUserHome": "false", "enable_localSystem": "true"})
        tree.write(distribution, encoding="utf-8", xml_declaration=True)
        resources = stage / "resources"
        resources.mkdir()
        html = '<html lang="ru"><meta charset="utf-8"><body style="font:15px -apple-system;line-height:1.5">'
        (resources / "welcome.html").write_text(html + '<h1>Shum в терминале</h1>'
            '<p>Установщик добавит команду <b>shum</b> в /usr/local/bin.</p>'
            '<p>Профили и переписка сохраняются.</p>'
            f'<p>Архитектура: {architecture}. Минимальная macOS: {minimum}.</p></body></html>')
        (resources / "conclusion.html").write_text(html + '<h1>Shum установлен</h1>'
            '<p>Откройте Terminal или Warp и выполните:</p><pre>shum</pre>'
            '<p>Первый запуск предложит создать профиль. Для списка чатов:</p><pre>shum chats</pre>'
            '<p>Если раньше вы ставили Shum через Cargo, команда <code>command -v shum</code> '
            'покажет используемую копию. Новая версия находится в <code>/usr/local/bin/shum</code>.</p>'
            '</body></html>')
        command = ["/usr/bin/productbuild", "--distribution", str(distribution),
                   "--package-path", str(stage), "--resources", str(resources)]
        if args.sign_installer:
            command += ["--sign", args.sign_installer]
        run(*command, str(package))
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    package.with_suffix(".pkg.sha256").write_text(f"{digest}  {package.name}\n")
    manifest = {"version": version, "architecture": architecture, "minimumMacOS": minimum,
                "package": package.name, "sha256": digest,
                "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "sourceRevision": source_revision, "signedInstaller": bool(args.sign_installer),
                "notarized": False, "embeddedExecutables": len(images)}
    package.with_suffix(".json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    archive = output / f"shum-{version}-macos-{architecture}.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        info = bundle.gettarinfo(str(binary), arcname="shum")
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mode = 0o755
        with binary.open("rb") as stream:
            bundle.addfile(info, stream)
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".gz.sha256").write_text(f"{archive_digest}  {archive.name}\n")
    formula_url = (args.release_base_url.rstrip("/") + "/" + archive.name
                   if args.release_base_url else archive.as_uri())
    # Quote Ruby literals without enabling interpolation in user-supplied URLs.
    ruby_url = "'" + formula_url.replace("\\", "\\\\").replace("'", "\\'") + "'"
    tap = output / "homebrew-shum"
    formula = tap / "Formula/shum.rb"
    formula.parent.mkdir(parents=True, exist_ok=True)
    formula.write_text(f'''class Shum < Formula
  desc "Private messenger in your terminal"
  homepage "https://github.com/hiTechTeam/Shum-Core"
  url {ruby_url}
  version "{version}"
  sha256 "{archive_digest}"
  license "MIT"

  depends_on arch: :{architecture}
  depends_on macos: :{macos_name}

  def install
    bin.install "shum"
  end

  test do
    assert_equal "shum {version}", shell_output("#{{bin}}/shum --version").strip
  end
end
''')
    (tap / "README.md").write_text(
        "# Shum Homebrew tap\n\n"
        "Формула устанавливает готовый бинарник и проверяет SHA-256.\n\n"
        "После публикации tap hiTechTeam/homebrew-shum:\n\n"
        "```sh\nbrew install hitechteam/shum/shum\nbrew upgrade shum\n```\n\n"
        + ("URL указывает на локальный архив. Перед публикацией пересоберите с "
           "`--release-base-url` и адресом каталога артефактов.\n" if not args.release_base_url else ""))
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    print(package)
    print(archive)
    print(formula)


if __name__ == "__main__":
    main()
