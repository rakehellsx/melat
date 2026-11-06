"""Configure native services using an existing local ClickHouse client XML.

Run as root after placing the app/venv and private TShark under /u3/melat.
Does not install, reconfigure or restart the existing ClickHouse service.
"""
import os
from pathlib import Path
import pwd
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET

root=Path('/u3/melat')
config=ET.parse(sys.argv[1]).getroot()
host=config.findtext('host','127.0.0.1')
port=config.findtext('port','9000')
user=urllib.parse.quote(config.findtext('user','default'),safe='')
password=urllib.parse.quote(config.findtext('password',''),safe='')
try:
    account=pwd.getpwnam('melat')
except KeyError:
    subprocess.run(['useradd','--system','--home-dir',str(root/'home'),'--shell','/sbin/nologin','melat'],check=True)
    account=pwd.getpwnam('melat')
for name in ('home','state','imports','native-tests'):
    path=root/name
    path.mkdir(exist_ok=True)
    os.chown(path,account.pw_uid,account.pw_gid)
    path.chmod(0o750)
envdir=Path('/etc/melat')
envdir.mkdir(mode=0o750,exist_ok=True)
os.chown(envdir,0,account.pw_gid)
env=envdir/'melat.env'
if env.exists():
    raise RuntimeError('Existing environment file: inspect before changing deployment')
env.write_text('\n'.join([
    f'DATABASE_URL=clickhouse+native://{user}:{password}@{host}:{port}/netmeta',
    f'MELAT_STATE_DIR={root}/state',f'PCAP_WORK_DIR={root}/imports',
    f'MELAT_TEST_ROOT={root}/native-tests',f'HOME={root}/home',
    f'PATH={root}/wireshark/bin:{root}/app/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin',
    f'LD_LIBRARY_PATH={root}/deps/lib:{root}/deps/lib64:{root}/wireshark/lib64:{root}/wireshark/lib',
    'PYTHONUNBUFFERED=1','TZ=UTC','']) )
env.chmod(0o640)
os.chown(env,0,account.pw_gid)
for name,module,memory,stop in [('web','uvicorn backend.main:app --host 0.0.0.0 --port 3000','4G',30),('worker','backend.ingest_worker','6G',60)]:
    path=Path('/etc/systemd/system')/f'melat-{name}.service'
    path.write_text(f'''[Unit]
Description=Melat native {name}
After=network.target clickhouse-server.service
Requires=clickhouse-server.service
[Service]
Type=simple
User=melat
Group=melat
WorkingDirectory={root}/app
EnvironmentFile=/etc/melat/melat.env
ExecStart={root}/app/.venv/bin/python -m {module}
Restart=on-failure
RestartSec=5
MemoryLimit={memory}
TimeoutStopSec={stop}
UMask=0027
[Install]
WantedBy=multi-user.target
''')
subprocess.run(['systemctl','daemon-reload'],check=True)
print('Native services configured; existing ClickHouse unchanged')
