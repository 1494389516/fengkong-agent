import unittest
from agent.investigation_plan import validate,template
class Plan(unittest.TestCase):
    def test_scope_and_cycles(self):
        snapshot={'entity_ref':'u','decision':{'event':{'event_id':'e'}},'allowed_tools':['get_event_evidence','feature_stats'],
                  'budget':{'max_tool_calls':4}}
        plan=template(snapshot,snapshot['allowed_tools'])
        self.assertEqual(len(validate(plan,snapshot,snapshot['allowed_tools'])),2)
        plan['nodes'][1]['args']['uid']='other'
        with self.assertRaises(PermissionError):validate(plan,snapshot,snapshot['allowed_tools'])
        plan['nodes'][1]['args']['uid']='u';plan['nodes'][0]['depends']=['business']
        with self.assertRaises(ValueError):validate(plan,snapshot,snapshot['allowed_tools'])
        plan['nodes'][0]['depends']=[];plan['nodes'][1]['tool']='blacklist_add'
        with self.assertRaises(PermissionError):validate(plan,snapshot,snapshot['allowed_tools'])
if __name__=='__main__':unittest.main()
