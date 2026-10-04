import unittest
from agent.claims import verify_assertion, audit_event_claims
class Claims(unittest.TestCase):
    def test_ref_is_not_enough(self):
        snap={'entity_ref':'u','as_of':200,'decision':{'event':{'uid':'u','event_id':'e','ts':100,'amount':8}}}
        a=dict(subject_ref='u',evidence_ref='event:e',field='amount',predicate='equals',value=8,unit='',time_window=[0,150])
        self.assertEqual(verify_assertion(a,snap)['status'],'supported')
        for field,value in [('value',9),('subject_ref','other'),('predicate','not_equals'),('unit','USD'),('time_window',[101,150])]:
            self.assertNotEqual(verify_assertion({**a,field:value},snap)['status'],'supported')
        report={'claims':[{'statement':'wrong','event_evidence':['event:e']}]}
        self.assertEqual(audit_event_claims(report,snap)['status'],'unverified')
if __name__=='__main__':unittest.main()
