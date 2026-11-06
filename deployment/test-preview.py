"""Run an isolated native preview without exposing credentials in arguments."""
import os,sys,importlib
from pathlib import Path
from backend import db
os.environ['DATABASE_URL']=db.DATABASE_URL.rsplit('/',1)[0]+'/netmeta_native_test'
root=Path(os.environ.get('MELAT_TEST_ROOT',str(Path(os.environ.get('MELAT_STATE_DIR','/tmp/melat-state')).parent/'native-tests')))
os.environ['MELAT_STATE_DIR']=str(root/'state')
os.environ['PCAP_WORK_DIR']=str(root/'imports')
importlib.reload(db)
if sys.argv[1]=='web':
    import uvicorn
    uvicorn.run('backend.main:app',host='127.0.0.1',port=3001)
else:
    from backend.ingest_worker import main
    main()
