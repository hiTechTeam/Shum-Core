#!/usr/bin/env python3
"""Check actual ANSI output in PTYs, without creating keys or starting a daemon.
Usage: terminal_display.py PATH_TO_SHUM [--legacy]
"""
import base64
import fcntl
import os
import pathlib
import pty
import re
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time

binary = str(pathlib.Path(sys.argv[1]).resolve())
legacy = "--legacy" in sys.argv[2:]
for program in (["Apple_Terminal"] if legacy else ["Apple_Terminal", "WarpTerminal"]):
    with tempfile.TemporaryDirectory(prefix="shum-display-") as directory:
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 80, 640, 640))
        before = termios.tcgetattr(slave)
        env = dict(os.environ, TERM="xterm-256color", TERM_PROGRAM=program)
        for name in ["COLORTERM", "KITTY_WINDOW_ID", "WT_SESSION", "NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE"]:
            env.pop(name, None)
        proc = subprocess.Popen([binary, "--data-dir", directory, "--no-bluetooth",
                                 "--relay", "ws://127.0.0.1:9", "--push-url", "off",
                                 "init", "--headless"], stdin=slave, stdout=slave,
                                stderr=slave, env=env, start_new_session=True)
        raw = bytearray()

        def pump(seconds):
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                if select.select([master], [], [], .05)[0]:
                    raw.extend(os.read(master, 65536))

        try:
            for _ in range(100):
                pump(.1)
                if "Имя:".encode() in raw:
                    break
            assert "Имя:".encode() in raw, raw[-1000:]
            os.write(master, b"Display test\r")
            pump(1)
            assert "Аватар".encode() in raw
            sgr = re.findall(rb"\x1b\[[0-?]*[ -/]*m", raw)
            rgb = any(re.search(rb"(?:38|48);2;", sequence) for sequence in sgr)
            if legacy:
                assert rgb
                print("REPRODUCED: RGB escape sequences sent to Apple Terminal")
            elif program == "Apple_Terminal":
                assert not rgb, "unsupported RGB output"
                assert any(b"48;5;232" in sequence for sequence in sgr), ("missing dark indexed background", sgr[:10])
                assert b"\x1b]1337;" not in raw
                assert not any(g.encode() in raw for g in "▀▄"), "portraits must be independent of font glyphs"
                assert b"Shum" in raw and "ШУМ".encode() not in raw
                print("PASS Apple Terminal: indexed colours, dark background, Shum title")
            else:
                assert rgb
                assert b'\x1b_Ga=d,d=I,' in raw, 'Warp requires explicit graphics deletion'
                assert b'\x1b]1337;' not in raw, 'do not use random iTerm image placements in Warp'
                pngs = re.findall(rb"\x1b_Ga=T,[^;]*;([A-Za-z0-9+/=]+)\x1b\\", raw)
                assert pngs, "Warp did not receive a native image"
                png = base64.b64decode(pngs[-1])
                assert png.startswith(b"\x89PNG\r\n\x1a\n")
                destination = pathlib.Path("/tmp/shum-terminal-review/warp-avatar.png")
                destination.parent.mkdir(exist_ok=True)
                destination.write_bytes(png)
                print("PASS Warp: RGB colours, native PNG and owned Kitty placements")
            os.write(master, b"\x11")
            proc.wait(timeout=3)
            assert proc.returncode == 0
            after = termios.tcgetattr(slave)
            flags = termios.ICANON | termios.ECHO
            assert before[3] & flags == after[3] & flags
            print("PASS Ctrl+Q restores the terminal")
            if not legacy and program == "Apple_Terminal":
                # Non-TUI commands use a separate avatar renderer.
                raw.clear()
                proc = subprocess.Popen([binary, "--data-dir", directory,
                                         "--no-bluetooth", "--relay", "ws://127.0.0.1:9",
                                         "--push-url", "off", "init", "--headless",
                                         "--name", "Display test"], stdin=slave,
                                        stdout=slave, stderr=slave, env=env,
                                        start_new_session=True)
                for _ in range(100):
                    pump(.1)
                    if proc.poll() is not None:
                        break
                assert proc.returncode == 0, raw[-1000:]
                assert b"48;5;" in raw and b"38;2;" not in raw and b"48;2;" not in raw
                assert not any(g.encode() in raw for g in "▀▄"), "standalone avatars must use backgrounds too"
                print("PASS Apple Terminal: standalone avatar uses indexed colours")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)
            os.close(slave)
