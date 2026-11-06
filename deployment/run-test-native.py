import importlib,os,unittest
from pathlib import Path
from backend import db
os.environ['DATABASE_URL']=db.DATABASE_URL.rsplit('/',1)[0]+'/netmeta_native_test'
root=Path(os.environ.get('MELAT_TEST_ROOT',str(Path(os.environ.get('MELAT_STATE_DIR','/tmp/melat-state')).parent/'native-tests')))
os.environ['MELAT_STATE_DIR']=str(root/'state')
os.environ['PCAP_WORK_DIR']=str(root/'imports')
importlib.reload(db)
suite=unittest.defaultTestLoader.discover('tests',pattern='test_clickhouse_native.py')
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not result.wasSuccessful())
