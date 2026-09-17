import test_completion_http as http_tests
import unittest
import time

class TypedHTTP(unittest.TestCase):
    setUp = http_tests.CompletionHTTP.setUp
    stop = http_tests.CompletionHTTP.stop
    request = http_tests.CompletionHTTP.request
    def test_typed_decision_wire_is_consumed(self):
        event={'kind':'business_risk_event','contract_version':1,'event_id':'typed','uid':'u',
               'type':'login','occurred_at_ms':int(time.time()*1000)}
        value={'kind':'decision_request','contract_version':1,'request_id':'req','business_event_id':'typed',
               'sdk_report_ids':[],'business_event':event}
        code,result=self.request('POST','/decisions','a-business',value)
        self.assertEqual(code,200,result)
        self.assertEqual(result['business_event_id'],'typed')
        code,result=self.request('POST','/decisions','a-sdk',value)
        self.assertEqual(code,403,result)
