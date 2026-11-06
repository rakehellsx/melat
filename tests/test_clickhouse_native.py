"""Integration tests against the exact ClickHouse version in a disposable database."""
import json,os,unittest
from pathlib import Path
from contextlib import ExitStack

ENABLED=os.environ.get('DATABASE_URL','').endswith('/netmeta_native_test')

@unittest.skipUnless(ENABLED,'Requires isolated netmeta_native_test database')
class NativeClickHouseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from backend.runtime_schema import ensure_runtime_schema
        from backend.db import command
        ensure_runtime_schema()
        for table in ('sessions','alerts','ingest_batches','ingest_jobs','custom_models','analysis_runs'):
            command(f'TRUNCATE TABLE {table}')
        from backend.pcap_parser import parse_pcap
        from backend.pcap_importer import import_flow_stream
        cls.capture=parse_pcap(Path('示例抓包文件.pcap').read_bytes())
        cls.imported=import_flow_stream(cls.capture['flows'],42)

    def test_a_exact_version_and_roundtrip(self):
        from backend.db import query_one,insert,execute
        self.assertEqual(query_one('SELECT version() v')['v'],'22.3.10.22')
        self.assertEqual(query_one('SELECT count() c FROM sessions')['c'],55)
        from backend.local_state import next_id
        identifier=insert('INSERT INTO custom_models (name,dimensions,metrics,filters,having_def) VALUES (%s,%s,%s,%s,%s)',("测试'\\\n%中文","[]","[]","[]",None))
        row=query_one('SELECT * FROM custom_models WHERE id=%s',(identifier,))
        self.assertEqual(row['name'],"测试'\\\n%中文")
        self.assertLess(identifier,2**53)
        execute('DELETE FROM custom_models WHERE id=%s',(identifier,))
        self.assertIsNone(query_one('SELECT id FROM custom_models WHERE id=%s',(identifier,)))
        self.assertEqual(query_one('SELECT count() c FROM sessions WHERE src_ip=%s',("' OR 1=1 --",))['c'],0)

    def test_b_all_model_fields_and_null_safe_matching(self):
        from backend.contracts import DIMENSIONS,METRIC_FIELDS
        from backend.model_engine import run_model,match_sessions_for_model
        from backend.db import query_one
        self.assertEqual(len(DIMENSIONS),176)
        for field in DIMENSIONS:
            with self.subTest(field=field['key']):
                definition={'name':'field-test','dimensions':[field['key']],
                            'metrics':[{'field':'*','agg':'count','alias':'count'}], 'filters':[], 'having':None}
                self.assertLessEqual(len(run_model(definition,page=1)['rows']),10)
                if field['numeric']:
                    definition['metrics']=[{'field':field['key'],'agg':'avg','alias':'avg'}]
                    run_model(definition,page=1)
        for field in ('httpHost','isNight','hourOfDay','threatScore'):
            definition={'dimensions':['srcIp'],'metrics':[{'field':field,'agg':'countDistinct','alias':'distinct'}],'filters':[],'having':None}
            run_model(definition,page=1)
        definition={'dimensions':['tlsSni'],'metrics':[{'field':'*','agg':'count','alias':'c'}],'filters':[],'having':None}
        result=match_sessions_for_model(definition)
        self.assertEqual(result['sessionTotal'],55)
        for value in ('true','false'):
            definition['filters']=[{'field':'isNight','op':'eq','value':value}]
            result=run_model(definition)
            expected=query_one('SELECT count() c FROM sessions WHERE JSONExtractRaw(meta,\'isNight\')=%s',(value,))['c']
            self.assertEqual(sum(row['m0'] for row in result['rows']),expected)

    def test_c_job_updates_and_failure_cleanup(self):
        from backend.db import insert,query_one,execute
        from backend.ingest_worker import fail_job
        insert('INSERT INTO ingest_jobs (id,filename,size_bytes,status) VALUES (%s,%s,%s,%s)',('failure-test','测试.pcap',10,'queued'))
        execute('UPDATE ingest_jobs SET status=%s,packets=%s WHERE id=%s',('processing',123,'failure-test'))
        row=query_one('SELECT * FROM ingest_jobs WHERE id=%s',('failure-test',))
        self.assertEqual((row['status'],row['packets']),('processing',123))
        fail_job(row,'test failure')
        self.assertEqual(query_one('SELECT * FROM ingest_jobs WHERE id=%s',('failure-test',))['status'],'failed')
        # Recovering the same failed job remains harmless.
        fail_job(row,'test failure')

    def test_d_all_analysis_rules(self):
        from backend.analysis_engine import run_all_analyses
        from backend.db import query_all
        results=run_all_analyses()
        self.assertEqual(len(results),14)
        self.assertTrue(all(row['status']=='success' for row in query_all('SELECT status FROM analysis_runs')))

    def test_e_import_lock_and_exact_deletion_counts(self):
        from backend.data_management import delete_records,data_write_connection,DataBusyError
        from backend.db import query_all,query_one
        from backend.pcap_importer import import_flow_stream
        ids=[row['id'] for row in query_all('SELECT id FROM sessions ORDER BY id LIMIT 12')]
        with data_write_connection():
            with self.assertRaises(DataBusyError):delete_records('sessions',{'ids':ids})
        self.assertEqual(delete_records('sessions',{'ids':ids})['deleted'],12)
        self.assertEqual(delete_records('sessions',{'ids':ids})['deleted'],0)
        with self.assertRaises(ValueError):delete_records('sessions',{},True)
        self.assertEqual(delete_records('sessions',{'confirm':'DELETE_ALL'},True)['deleted'],43)
        self.assertEqual(query_one('SELECT count() c FROM sessions')['c'],0)
        import_flow_stream(self.capture['flows'],42)
        delete_records('alerts',{'confirm':'DELETE_ALL'},True)

    def test_f_long_duration_and_id_uniqueness(self):
        from backend.db import query_one,execute
        from backend.local_state import reserve_ids
        values=list(reserve_ids(1000));self.assertEqual(len(set(values)),1000)
        first=query_one('SELECT id,duration FROM sessions ORDER BY id LIMIT 1')
        execute('UPDATE sessions SET duration=%s WHERE id=%s',(24026239874,first['id']))
        self.assertEqual(query_one('SELECT duration FROM sessions WHERE id=%s',(first['id'],))['duration'],24026239874)
        execute('UPDATE sessions SET duration=%s WHERE id=%s',(first['duration'],first['id']))

    def test_g_full_group_pages_beyond_500(self):
        from backend.db import query_one,query_all,insert_rows,execute
        from backend.local_state import reserve_ids
        from backend.model_engine import run_model,match_sessions_for_model
        template=query_one('SELECT * FROM sessions LIMIT 1')
        rows=[]
        for i,identifier in enumerate(reserve_ids(620)):
            rows.append({**template,'id':identifier,'session_id':f'pagination-native-{i}',
                         'src_ip':f'192.0.{i//250}.{i%250+1}'})
        insert_rows('sessions',rows)
        definition={'dimensions':['srcIp'],'metrics':[{'field':'*','agg':'count','alias':'c'}],
                    'filters':[{'field':'sessionId','op':'like','value':'pagination-native-'}],'having':None}
        page=run_model(definition,page=62)
        self.assertEqual((page['total'],len(page['rows'])),(620,10))
        matches=match_sessions_for_model(definition,page=62,groups_page=62)
        self.assertEqual((matches['sessionTotal'],len(matches['sessions'])),(620,10))
        execute('DELETE FROM sessions WHERE session_id LIKE %s',('pagination-native-%',))

    def test_h_disk_spooling_restores_evicted_flow_state(self):
        import struct,tempfile
        from backend.pcap_parser import parse_pcap_file
        from test_pcap_parser import pcap,udp_dns
        frames=[]
        for response in (False,True):
            for i in range(320):
                frame=bytearray(udp_dns(response))
                struct.pack_into('!H',frame,36 if response else 34,54000+i)
                frames.append(bytes(frame))
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'eviction.pcap';source.write_bytes(pcap(frames))
            with parse_pcap_file(source,cache_size=8) as result:
                flows=list(result['flows'])
                self.assertEqual((result['packets'],len(flows)),(640,320))
                self.assertTrue(all((f['upPackets'],f['downPackets'])==(1,1) for f in flows))
            self.assertFalse(source.with_suffix('.flows.sqlite').exists())

if __name__=='__main__':unittest.main(verbosity=2)
