#!/usr/bin/env python3
"""Exercise CLI colours in a real PTY, with a disposable local snapshot server.
No real profiles, Keychain, Bluetooth or remote relays are used.
Usage: command_colors.py PATH_TO_SHUM
"""
import copy
import fcntl
import json
import os
import pathlib
import pty
import re
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

binary = str(pathlib.Path(sys.argv[1]).resolve())
SGR = re.compile(rb"\x1b\[[0-?]*[ -/]*m")
ESC = b"\x1b"
preview = pathlib.Path("/tmp/shum-command-colors-review")
preview.mkdir(exist_ok=True)


def environment(program):
    env = dict(os.environ, TERM="xterm-256color", TERM_PROGRAM=program)
    for name in ["COLORTERM", "KITTY_WINDOW_ID", "WT_SESSION", "NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "FORCE_COLOR"]:
        env.pop(name, None)
    return env


def read_exact(stream, count):
    data = b""
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


with tempfile.TemporaryDirectory(prefix="shum-command-colors-") as directory:
    root = pathlib.Path(directory)
    command = [binary, "--data-dir", directory]
    created = subprocess.run(command + ["--json", "--no-bluetooth", "--relay", "ws://127.0.0.1:9",
                             "--push-url", "off", "init", "--headless", "--name", "Проверка цветов"],
                             capture_output=True, timeout=15, check=True)
    created = json.loads(created.stdout)
    own = created["profile"]
    anna = copy.deepcopy(created["card"])
    anna["name"] = "Аня"
    anna.pop("avatarSeed", None)  # Text-command tests do not negotiate native images.
    card = copy.deepcopy(created["card"])
    card.pop("avatarSeed", None)
    snapshot = {"profile": own, "card": card, "relays": ["wss://test.invalid"],
                "bluetooth": {"enabled": True, "scan": "scanning", "advertise": "advertising"},
                "pushConfigured": False,
                "contacts": [{"id": "anna", "card": anna, "nearby": True, "distance": 3,
                              "unread": 1, "phase": "accepted"},
                             {"id": "igor", "card": {"name": "Игорь"}, "unread": 0,
                              "phase": "incomingPending", "nearby": False}],
                "messages": [{"id": "one", "contactID": "anna", "text": "Привет, проверяем цвета!",
                              "timestamp": int(time.time() * 1000)}]}
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(.2)
    token = os.urandom(32)
    endpoint = root / own["id"] / "daemon.json"
    endpoint.write_text(json.dumps({"port": listener.getsockname()[1], "token": token.hex(), "pid": os.getpid()}))
    endpoint.chmod(0o600)
    # Prevent a failed fixture connection from launching any real daemon.
    (root / own["id"] / "locked").touch()
    stopped = threading.Event()
    errors = []

    def serve():
        while not stopped.is_set():
            try:
                stream, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with stream:
                    stream.settimeout(5)
                    assert read_exact(stream, 32) == token
                    size, = struct.unpack(">I", read_exact(stream, 4))
                    request = json.loads(read_exact(stream, size))
                    assert request["command"] == "snapshot", request
                    body = json.dumps({"ok": snapshot}, ensure_ascii=False).encode()
                    stream.sendall(struct.pack(">I", len(body)) + body)
            except Exception as error:
                errors.append(error)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()

    def capture(args, program="Apple_Terminal", override=None, expected=0, tty=True):
        env = environment(program)
        env.update(override or {})
        if not tty:
            result = subprocess.run(command + args, env=env, capture_output=True, timeout=10)
            assert result.returncode == expected, result.stderr
            return result.stdout + result.stderr
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios_size, struct.pack("HHHH", 32, 80, 640, 640))
        proc = subprocess.Popen(command + args, stdin=slave, stdout=slave, stderr=slave,
                                env=env, start_new_session=True)
        raw = bytearray()
        try:
            end = time.monotonic() + 10
            while time.monotonic() < end:
                if select.select([master], [], [], .05)[0]:
                    raw.extend(os.read(master, 65536))
                elif proc.poll() is not None:
                    break
            assert proc.poll() == expected, (args, proc.poll(), bytes(raw)[-1500:])
            return bytes(raw)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)
            os.close(slave)

    import termios
    termios_size = termios.TIOCSWINSZ
    try:
        cases = [["chats"], ["nearby"], ["status"], ["about"], ["contacts"],
                 ["profile"], ["profile", "list"], ["keys", "verify", "Аня"], ["--help"]]
        for program in ["Apple_Terminal", "WarpTerminal"]:
            for args in cases:
                raw = capture(args, program)
                assert SGR.search(raw), (program, args, "missing colour")
                if program == "Apple_Terminal":
                    assert not re.search(rb"(?:38|48);2;", raw), "RGB sent to Apple Terminal"
                if args in [["chats"], ["about"]]:
                    (preview / (program + "-" + args[0] + ".ansi")).write_bytes(raw)
                if args == ["chats"]:
                    if program == "WarpTerminal":
                        assert b"38;2;48;209;88" in raw  # nearby + unread
                        assert b"38;2;255;214;10" in raw  # invitation
                        assert b"38;2;83;214;255" in raw  # command hints
                    else:
                        assert len(set(SGR.findall(raw))) >= 5
                    assert "приглашение в чат".encode() in raw
                if args == ["about"]:
                    assert raw.count("██".encode()) >= 7
                    assert "Система".encode() in raw and b"80\xc3\x9732" in raw
            raw = capture(["keys", "verify", "missing"], program, expected=1)
            assert SGR.search(raw)
            print(f"PASS {program}: coloured commands, errors, logo and palette")

        for args in cases:
            assert ESC not in capture(args + ["--ascii"]), (args, "ASCII contains escapes")
            assert ESC not in capture(args, override={"NO_COLOR": "1"}), (args, "NO_COLOR ignored")
            assert ESC not in capture(args, override={"TERM": "dumb"}), (args, "dumb terminal has escapes")
            assert ESC not in capture(args, tty=False), (args, "pipe contains escapes")
            raw = capture(args + ["--json"])
            assert ESC not in raw
            json.loads(raw)
        print("PASS --ascii, NO_COLOR, TERM=dumb, pipes and --json stay free of ANSI escapes")
        raw = capture(["chats"], override={"NO_COLOR": ""})
        assert SGR.search(raw), "empty NO_COLOR must not disable colours"
        for flag, present, absent in [("--nearby", "Аня", "Игорь"), ("--invites", "Игорь", "Аня"), ("--unread", "Аня", "Игорь")]:
            raw = capture(["chats", flag])
            assert present.encode() in raw and absent.encode() not in raw
        assert not errors, errors
        print("PASS chat filters preserve their selection; previews:", preview)
    finally:
        stopped.set()
        listener.close()
        worker.join(timeout=2)
