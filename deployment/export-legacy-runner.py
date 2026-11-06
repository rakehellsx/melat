"""Read legacy container configuration locally without printing credentials."""
import json,os,subprocess,sys
from pathlib import Path
from urllib.parse import urlparse,urlunparse

app=json.loads(subprocess.check_output(['docker','inspect','melat-app-1']))[0]
database=json.loads(subprocess.check_output(['docker','inspect','melat-db-1']))[0]
values=dict(item.split('=',1) for item in app['Config']['Env'] if '=' in item)
address=next(iter(database['NetworkSettings']['Networks'].values()))['IPAddress']
url=urlparse(values['DATABASE_URL']);credentials=url.netloc.rsplit('@',1)[0]
values['DATABASE_URL']=urlunparse(url._replace(netloc=credentials+'@'+address+':3306'))
env=os.environ.copy();env.update(values);env['PYTHONPATH']='/opt/melat'
subprocess.run(['/data/melat/test-venv/bin/python','/opt/melat/export-mysql.py',sys.argv[1]],env=env,check=True,cwd='/opt/melat')
