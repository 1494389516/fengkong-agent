import os,tempfile,unittest
from unittest.mock import patch
from agent.event_bus import event_bus
class Groups(unittest.TestCase):
    def test_independent_groups_and_dead_letters(self):
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{'FK_DATA_DIR':root}):
            event_bus().publish('risk','key',{'x':1})
            groups=[event_bus(name) for name in ('graph','feature','case')]
            events=[g.claim('risk')[0] for g in groups]
            self.assertEqual(len({e.event_id for e in events}),1)
            self.assertTrue(groups[0].acknowledge(events[0].event_id,events[0].lease_token))
            self.assertEqual(groups[0].claim('risk'),[])
            self.assertTrue(groups[1].fail(events[1].event_id,events[1].lease_token,'failure',max_attempts=1))
            self.assertEqual(len(groups[1].dead_letters()),1)
            self.assertTrue(groups[2].acknowledge(events[2].event_id,events[2].lease_token))
            self.assertFalse(groups[0].acknowledge(events[0].event_id,events[0].lease_token))
if __name__=='__main__':unittest.main()
