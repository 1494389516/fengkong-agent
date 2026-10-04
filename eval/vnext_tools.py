import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
class Tools(unittest.TestCase):
    def test_evidence_not_recropped(self):
        from agent.tool_contracts import evidence_view
        value={'signals':[{'ref':str(n),'detected':n==21} for n in range(32)],
               'limitations':['x'*1000], 'refs':{str(n):n for n in range(40)}}
        result=evidence_view(value)
        self.assertEqual(len(result['signals']),32)
        self.assertEqual(len(result['refs']),40)
        self.assertEqual(result['limitations'],value['limitations'])
    def test_invalid_arguments_close_audit(self):
        from agent.tools import dispatch
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'FK_DATA_DIR':root}):
            result=dispatch('get_event_evidence',{'event_id':False})
            self.assertIn('error',result)
            rows=[json.loads(line) for line in (Path(root)/'governance_audit.jsonl').read_text().splitlines()]
            self.assertEqual(rows[-1]['phase'],'post_tool')
            self.assertEqual(rows[-1]['decision']['outcome'],'deny')
if __name__=='__main__':unittest.main()
