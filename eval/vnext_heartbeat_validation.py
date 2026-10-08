import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from agent.event_bus import event_bus
from agent.graph_worker_health import write_heartbeat, read_health


class HeartbeatValidation(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        env=patch.dict(os.environ,{'FK_DATA_DIR':tmp.name});env.start();self.addCleanup(env.stop)
        self.path=Path(tmp.name)/'out'/'graph_worker_health.json'
        self.valid=write_heartbeat({'processed':0,'failed':[]},event_bus().stats(),now=1000)

    def read(self,payload):
        self.path.write_text(json.dumps(payload))
        return read_health(now=1000)

    def test_invalid_timestamp_never_healthy(self):
        for value in (float('nan'),float('inf'),float('-inf'),1001,True,'1000',-1):
            with self.subTest(value=value):
                p={**self.valid,'updated_at':value}
                self.assertEqual(self.read(p)['level'],'degraded')

    def test_missing_and_mistyped_fields_fail_closed(self):
        for section in ('bus','projection'):
            for value in ({},[],None,'bad',False):
                with self.subTest(section=section,value=value):
                    self.assertEqual(self.read({**self.valid,section:value})['level'],'degraded')
            for field in self.valid[section]:
                if field=='topic':continue
                p=copy.deepcopy(self.valid);del p[section][field]
                with self.subTest(section=section,missing=field):
                    self.assertEqual(self.read(p)['level'],'degraded')
        for field in ('processed','failed','updated_at','topic'):
            p=copy.deepcopy(self.valid);del p[field]
            self.assertEqual(self.read(p)['level'],'degraded')

    def test_bad_numbers_do_not_escape_to_readiness(self):
        for section in ('bus','projection'):
            for field in self.valid[section]:
                if field=='topic':continue
                for value in ('broken',None,True,-1,float('nan'),float('inf'),[],{}):
                    p=copy.deepcopy(self.valid);p[section][field]=value
                    with self.subTest(section=section,field=field,value=value):
                        self.assertEqual(self.read(p)['level'],'degraded')

    def test_inconsistent_counts_and_ratio_rejected(self):
        for changes in ({'total':1},{'availability':0.5},{'available':1},{'unavailable':1}):
            p=copy.deepcopy(self.valid);p['projection'].update(changes)
            self.assertEqual(self.read(p)['level'],'degraded')
        p=copy.deepcopy(self.valid);p['bus']['ready']=1
        self.assertEqual(self.read(p)['level'],'degraded')

    def test_valid_stale_missing_and_corrupt(self):
        self.assertEqual(self.read(self.valid)['level'],'ok')
        self.assertEqual(read_health(now=1011)['reason'],'heartbeat_stale')
        for raw in ('{','[]','null','"text"','{"updated_at":NaN}', '\ud800'):
            self.path.write_bytes(raw.encode('utf-8',errors='surrogatepass'))
            self.assertEqual(read_health(now=1000)['reason'],'heartbeat_invalid')
        self.path.unlink()
        self.assertEqual(read_health(now=1000)['reason'],'heartbeat_missing')

    def test_read_io_size_and_configuration_errors_degrade(self):
        with patch.object(Path,'open',side_effect=PermissionError('denied')):
            self.assertEqual(read_health(now=1000)['reason'],'heartbeat_invalid')
        self.path.write_bytes(b' '*65537)
        self.assertEqual(read_health(now=1000)['reason'],'heartbeat_invalid')
        for kwargs in ({'now':float('nan')},{'max_age_seconds':float('inf')},
                       {'max_backlog_age_seconds':-1},{'now':True}):
            self.assertEqual(read_health(**kwargs)['reason'],'health_config_invalid')

    def test_invalid_writer_does_not_replace_previous_heartbeat(self):
        before=self.path.read_bytes()
        for value in (float('nan'),float('inf'),True,'1000',-1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    write_heartbeat({'processed':0,'failed':[]},event_bus().stats(),now=value)
                self.assertEqual(self.path.read_bytes(),before)


if __name__=='__main__':unittest.main()
