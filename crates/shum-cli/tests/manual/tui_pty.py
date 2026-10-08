#!/usr/bin/env python3
"""macOS/Unix PTY regression. Uses disposable profiles; no third-party Python packages.
Usage: python3 .../tui_pty.py target/debug/shum [--native-first-run]
"""
import shutil, codecs, unicodedata, base64, fcntl, json, os, pathlib, pty, re, select, signal, struct, subprocess, sys, tempfile, termios, time
BIN = str(pathlib.Path(sys.argv[1]).resolve())
NATIVE = '--native-first-run' in sys.argv[2:]
ESCAPE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)')
ROOT = pathlib.Path(tempfile.mkdtemp(prefix='shum-tui-')) / 'profiles'
# Keep the executable identity stable even if another test rebuilds target/debug/shum.
shutil.copy2(BIN, ROOT.parent / 'shum')
BIN = str(ROOT.parent / 'shum')
CHILDREN = []
def cli(*args, ok=True):
    result = subprocess.run([BIN, '--data-dir', str(ROOT), '--json', *args], capture_output=True, text=True, timeout=35)
    assert (result.returncode == 0) == ok, (args, result.stdout, result.stderr)
    return json.loads(result.stdout)
class Screen:
    def __init__(self):
        self.rows = [[' '] * 80 for _ in range(32)]; self.x = self.y = 0
        self.pending = ''; self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
    def feed(self, data):
        self.pending += self.decoder.decode(data)
        while self.pending:
            if self.pending.startswith('\x1b['):
                match=re.match(r'\x1b\[([0-?]*)([ -/]*)([@-~])',self.pending)
                if not match: break
                raw,_,cmd=match.groups(); self.pending=self.pending[match.end():]
                parts=[int(p) if p.isdigit() else 0 for p in raw.lstrip('?').split(';')]; n=parts[0] or 1
                if cmd in 'Hf':self.y=(parts[0] or 1)-1;self.x=(parts[1] if len(parts)>1 and parts[1] else 1)-1
                elif cmd=='A':self.y=max(0,self.y-n)
                elif cmd=='B':self.y=min(31,self.y+n)
                elif cmd=='C':self.x=min(79,self.x+n)
                elif cmd=='D':self.x=max(0,self.x-n)
                elif cmd=='G':self.x=n-1
                elif cmd=='d':self.y=n-1
                elif cmd=='J':
                    if parts[0] in (2,3): self.rows=[[' ']*80 for _ in range(32)]
                    elif parts[0]==0:
                        self.rows[self.y][self.x:]=[' ']*(80-self.x)
                        for y in range(self.y+1,32):self.rows[y]=[' ']*80
                elif cmd=='K':
                    start=0 if parts[0] in (1,2) else self.x; end=self.x+1 if parts[0]==1 else 80
                    self.rows[self.y][start:end]=[' ']*(end-start)
                elif cmd=='h' and raw=='?1049':self.rows=[[' ']*80 for _ in range(32)];self.x=self.y=0
                continue
            if self.pending.startswith('\x1b'):
                if len(self.pending)<2:break
                self.pending=self.pending[2:];continue
            c=self.pending[0];self.pending=self.pending[1:]
            if c=='\r':self.x=0
            elif c=='\n':self.y+=1
            elif c=='\b':self.x=max(0,self.x-1)
            elif ord(c)>=32:
                if self.x>=80:self.x=0;self.y+=1
                if self.y>=32:self.rows.pop(0);self.rows.append([' ']*80);self.y=31
                if not unicodedata.combining(c):
                    self.rows[self.y][self.x]=c
                    self.x += 2 if unicodedata.east_asian_width(c) in ('W','F') else 1
            if self.y>=32:self.rows.pop(0);self.rows.append([' ']*80);self.y=31
    def text(self):return '\n'.join(''.join(row) for row in self.rows)

class Terminal:
    def __init__(self, *args):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH',32,80,640,640))
        self.before = termios.tcgetattr(slave)
        env = dict(os.environ, TERM='xterm-256color')
        for name in ['TERM_PROGRAM','KITTY_WINDOW_ID','WT_SESSION']: env.pop(name,None)
        self.proc = subprocess.Popen([BIN,'--data-dir',str(ROOT),*args],stdin=slave,stdout=slave,stderr=slave,env=env,start_new_session=True)
        self.slave = slave; self.raw = b''; self.screen=Screen(); CHILDREN.append(self)
    def read(self, duration=.15):
        end=time.monotonic()+duration
        while time.monotonic()<end:
            if select.select([self.master],[],[],min(.05,max(0,end-time.monotonic())))[0]:
                try:
                    data=os.read(self.master,65536);self.raw+=data;self.screen.feed(data)
                except OSError: break
        return self.screen.text()
    def expect(self, value, timeout=8):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if re.sub(r"\s+", "", value) in re.sub(r"\s+", "", self.read()): return
            if self.proc.poll() is not None: break
        raise AssertionError(f'missing {value!r}: {self.read()[-2200:]}')
    def send(self, text):
        os.write(self.master,text.encode()); self.read()
    def exit(self, keys):
        start=time.monotonic();self.send(keys)
        while self.proc.poll() is None and time.monotonic()-start<2: self.read(.05)
        assert self.proc.poll()==0, (keys, self.proc.poll(),self.read()[-1500:])
        after=termios.tcgetattr(self.slave)
        assert after[3] & (termios.ICANON|termios.ECHO) == self.before[3] & (termios.ICANON|termios.ECHO), 'terminal left in raw mode'
        print(f'PASS exit {keys!r}: {time.monotonic()-start:.2f}s')
    def close(self):
        if self.proc.poll() is None: self.proc.kill(); self.proc.wait()
        os.close(self.master);os.close(self.slave)
try:
    # First launch offers registration automatically. Cancellation publishes nothing.
    t=Terminal('--relay','ws://127.0.0.1:9','--push-url','off')
    t.expect('Как вас зовут?');t.exit('\x1b')
    assert not cli('profile','list')['profiles']; print('PASS first-run cancellation')
    args=['--relay','ws://127.0.0.1:9','--push-url','off']
    if not NATIVE: args += ['init','--headless']
    t=Terminal(*args);t.expect('Как вас зовут?');t.send('\r');t.expect('Имя: 1–64')
    t.send('Проверка\r');t.expect('другой вариант');t.send('r');t.send('к');t.send('\r');t.expect('Профиль готов',20);t.send('\r')
    if NATIVE: t.expect('Пока нет чатов');t.exit('q')
    else:
        assert t.proc.wait(timeout=3)==0
    listing=cli('profile','list');assert len(listing['profiles'])==1
    aid=listing['selected'];a=cli('-p',aid,'profile');assert a['card']['name']=='Проверка';a['card']['avatarSeed']; print('PASS name, random avatar, saved profile')
    b=cli('--relay','ws://127.0.0.1:9','--push-url','off','init','--headless','--name','Друг')
    bid=b['profile']['id'];cli('profile','use',aid)
    # Unknown navigation characters no longer trap shortcuts in invisible input.
    for key in ['i','ш']:
        t=Terminal('-p',aid);t.expect('Пока нет чатов');t.send('xы');t.send(key);t.expect('Мой QR');t.send('\x1b');t.exit('q' if key=='i' else 'й')
    t=Terminal('-p',aid,'--ascii');t.expect('Пока нет чатов');t.send('i');t.expect('shum://c2/');t.exit('\x03')
    # Help, invalid arguments, visible command line and command aliases.
    for command in ['/quit','/exit','/q']:
        t=Terminal('-p',aid);t.expect('Пока нет чатов');t.send('/help\r');t.expect('Команды в Shum');t.send('\x1b');t.send('/accept extra extra\r');t.expect('не распознаны');t.send('\x1b');t.exit(command+'\r')
    t=Terminal('-p',aid);t.expect('Пока нет чатов');t.send('\x10');t.expect('Создать новый профиль');t.send('\x1b[B\x1b[B\r');t.expect('Как вас зовут?');t.send('\x1b');t.expect('Пока нет чатов');t.exit('\x11')
    assert len(cli('profile','list')['profiles'])==2;print('PASS profile chooser and cancelled new profile')
    cli('-p',aid,'add',b['invitation'])
    t=Terminal('-p',aid,'ui','Друг');t.expect('Сообщение');t.send('qiйшаф123');t.expect('qiйшаф123');t.send('\x1b');t.send('i');t.expect('Мой QR');t.send('\x1b');t.exit('q')
    assert cli('-p',aid,'status')['messages']==[];print('PASS editing does not execute q/i shortcuts')
    # A c2 lookup is pending for up to 20 seconds; UI must still accept exit.
    link='shum://c2/'+base64.urlsafe_b64encode(bytes.fromhex(b['card']['nostrKey'])).decode().rstrip('=')
    for quit_key in ['\x03','\x11','\x1b[21~']:
        t=Terminal('-p',aid);t.expect('Чаты');t.send('/add '+link+'\r');t.expect('Выполняется');t.exit(quit_key)
    # An unresponsive daemon must not trap the terminal either.
    endpoint=json.loads((ROOT/aid/'daemon.json').read_text());pid=endpoint['pid']
    t=Terminal('-p',aid);t.expect('Чаты');os.kill(pid,signal.SIGSTOP)
    try: t.read(.4);t.exit('\x03')
    finally: os.kill(pid,signal.SIGCONT)
    print('PASS stalled daemon remains interruptible')
    print('PASS all PTY scenarios')
finally:
    for child in CHILDREN: child.close()
    if ROOT.exists():
        try:
            for profile in cli('profile','list')['profiles']:
                cli('-p',profile['id'],'daemon','--stop')
                cli('profile','delete',profile['id'],'--confirm',profile['name'])
        finally:
            print('Disposable test directory:',ROOT)
