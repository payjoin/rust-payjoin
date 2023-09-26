
import unittest
import pdkpython as pdk


class TestURIs(unittest.TestCase):
        
    def test_valid_uris(self):
        
        https = "https://example.com"
        onion = "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion"
        
        base58 = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"
        bech32_upper = "BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4"
        bech32_lower = "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4"
        
        for address in [base58, bech32_upper, bech32_lower]:
            for pj in [https, onion]:
                uri = f"{address}?amount=1&pj={pj}"
                try:
                       pdk.Uri(uri)
                except Exception as e: 
                        self.fail(f"Failed to create a valid Uri for {uri}. Error: {e}") 

if __name__ == '__main__':
    unittest.main()
