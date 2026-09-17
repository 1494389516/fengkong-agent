import unittest
import serve

class PublicContractTests(unittest.TestCase):
    def test_release_authority_survives_public_dto(self):
        record={'runtime_activation_id':'activation-1','runtime_bundle_versions':{'policy':'p1'}}
        result=serve._public_view(record,False)
        self.assertEqual(result.get('runtime_activation_id'),'activation-1')
        self.assertEqual(result.get('runtime_bundle_versions'),{'policy':'p1'})

    def test_client_cannot_inject_server_identity_or_knowledge_time(self):
        for key,value in [('identity_trust','server_bound'),('entity_generation','1'),
                          ('recorded_at',1),('evidence_refs',['ev']),('hardware_attributes',{})]:
            with self.subTest(key=key):
                self.assertTrue(serve._validate_event({'event_id':'e','uid':'u','type':'login','ts':100,
                                                     key:value},now=100,source_kind='business'))
