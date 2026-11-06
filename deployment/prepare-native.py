"""Run as root on Ubuntu after extracting the source and the official ClickHouse package."""
import hashlib,os,pwd,grp,secrets,shutil,subprocess
from pathlib import Path

root=Path('/opt/melat-native')
for user in ('clickhouse','melat'):
    try:pwd.getpwnam(user)
    except KeyError:subprocess.run(['useradd','--system','--user-group','--home-dir',f'/data/melat/{user}','--shell','/usr/sbin/nologin',user],check=True)
etc=Path('/etc/melat');etc.mkdir(mode=0o750,exist_ok=True)
for directory,user in [('/data/melat/clickhouse','clickhouse'),('/data/melat/melat','melat'),('/data/melat/native-state','melat'),('/data/melat/native-imports','melat')]:
    p=Path(directory);p.mkdir(parents=True,exist_ok=True)
    shutil.chown(p,user=user,group=user)
for name in ('data','tmp','access','log','user_files','format_schemas'):
    p=Path('/data/melat/clickhouse')/name;p.mkdir(exist_ok=True);shutil.chown(p,user='clickhouse',group='clickhouse')
shutil.chown(etc,group='melat')
admin_path=etc/'clickhouse-admin.secret'
if not admin_path.exists():admin_path.write_text(secrets.token_hex(24));admin_path.chmod(0o600)
app_path=etc/'melat.env'
if not app_path.exists():
    password=secrets.token_hex(24)
    app_path.write_text(f'DATABASE_URL=clickhouse://melat:{password}@127.0.0.1:8123/netmeta\nPCAP_WORK_DIR=/data/melat/native-imports\nMELAT_STATE_DIR=/data/melat/native-state\nTZ=UTC\n')
    app_path.chmod(0o640);shutil.chown(app_path,group='melat')
else:
    from urllib.parse import urlparse
    values=dict(line.split('=',1) for line in app_path.read_text().splitlines() if '=' in line)
    password=urlparse(values['DATABASE_URL']).password
users=etc/'clickhouse-users.xml'
admin_hash=hashlib.sha256(admin_path.read_text().encode()).hexdigest()
app_hash=hashlib.sha256(password.encode()).hexdigest()
users.write_text(f'''<clickhouse><profiles><default><max_memory_usage>1073741824</max_memory_usage><max_threads>2</max_threads><background_pool_size>4</background_pool_size><background_schedule_pool_size>4</background_schedule_pool_size><max_block_size>8192</max_block_size><log_queries>0</log_queries></default></profiles>
<users><default><password_sha256_hex>{admin_hash}</password_sha256_hex><networks><ip>127.0.0.1</ip></networks><profile>default</profile><quota>default</quota><access_management>1</access_management></default>
<melat><password_sha256_hex>{app_hash}</password_sha256_hex><networks><ip>127.0.0.1</ip></networks><profile>default</profile><quota>default</quota><allow_databases><database>netmeta</database><database>netmeta_native_test</database></allow_databases></melat></users><quotas><default><interval><duration>3600</duration><queries>0</queries><errors>0</errors><result_rows>0</result_rows><read_rows>0</read_rows><execution_time>0</execution_time></interval></default></quotas></clickhouse>''')
users.chmod(0o640);shutil.chown(users,group='clickhouse')
# Both service accounts need to traverse the configuration directory.
subprocess.run(['usermod','-a','-G','melat','clickhouse'],check=True)
shutil.copy2(root/'deployment/clickhouse.xml',etc/'clickhouse.xml')
for filename in ('clickhouse-server.service','melat-web.service','melat-worker.service'):
    shutil.copy2(root/'deployment'/filename,Path('/etc/systemd/system')/filename)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','clickhouse-server'],check=True)
print('ClickHouse service configured; credentials stored in /etc/melat with restricted permissions')
