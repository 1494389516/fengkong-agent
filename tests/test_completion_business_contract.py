import unittest

class BusinessContractTests(unittest.TestCase):
    def event(self):
        return {'kind':'business_risk_event','contract_version':1,'event_id':'e','uid':'u',
                'type':'login','occurred_at_ms':1789603200123}

    def test_typed_event_converts_milliseconds_once(self):
        from agent.contracts.business_contract import decision_event
        event=self.event()
        request={'kind':'decision_request','contract_version':1,'request_id':'r','business_event_id':'e',
                 'sdk_report_ids':['s'],'business_event':event}
        result=decision_event(request)
        self.assertEqual(result['ts'],1789603200.123)
        self.assertEqual(result['report_ids'],['s'])
        self.assertEqual(result['decision_request_id'],'r')

    def test_wrong_domain_units_and_server_fields_rejected(self):
        from agent.contracts.business_contract import decision_event
        request={'kind':'decision_request','contract_version':1,'request_id':'r','business_event_id':'e',
                 'sdk_report_ids':[],'business_event':self.event()}
        for change in [{'kind':'sdk_report'},{'occurred_at_ms':1789603200},
                       {'received_at_ms':1789603200123},{'identity_trust':'server_bound'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):
                decision_event({**request,'business_event':{**self.event(),**change}})
        with self.assertRaises(ValueError): decision_event({**request,'business_event_id':'different'})
