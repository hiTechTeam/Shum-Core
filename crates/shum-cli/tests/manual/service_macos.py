#!/usr/bin/env python3
"""Exercise launchd install/stop for a disposable profile, then remove the launch agent."""
import json, os, pathlib, shutil, subprocess, sys, tempfile, time
assert sys.platform=='darwin'
with tempfile.TemporaryDirectory(prefix='shum-launchd-') as directory:
    work=pathlib.Path(directory);root=work/'profiles';binary=work/'shum'
    shutil.copy2(sys.argv[1],binary)
    def cli(*args):
        p=subprocess.run([str(binary),'--data-dir',str(root),'--json',*args],capture_output=True,text=True,timeout=35)
        assert p.returncode==0,(args,p.stdout,p.stderr)
        return json.loads(p.stdout)
    created=cli('--relay','ws://127.0.0.1:9','--push-url','off','init','--headless','--name','Launchd test')
    pid=created['profile']['id'];label='org.shum.cli.'+pid;service=f'gui/{os.getuid()}/{label}'
    plist=pathlib.Path.home()/'Library/LaunchAgents'/f'{label}.plist'
    try:
        cli('status');old=json.loads((root/pid/'daemon.json').read_text())['pid']
        cli('daemon','--install')
        for _ in range(100):
            path=root/pid/'daemon.json'
            if path.exists() and json.loads(path.read_text())['pid']!=old:break
            time.sleep(.1)
        endpoint=json.loads(path.read_text());assert endpoint['pid']!=old
        status=subprocess.run(['launchctl','print',service],capture_output=True,text=True)
        assert status.returncode==0 and f'pid = {endpoint["pid"]}' in status.stdout,status.stdout
        cli('status');cli('daemon','--stop');assert not path.exists()
        print('PASS launchd took over existing daemon and stopped cleanly')
    finally:
        subprocess.run(['launchctl','bootout',service],capture_output=True)
        plist.unlink(missing_ok=True)
        cli('profile','delete',pid,'--confirm','Launchd test')
