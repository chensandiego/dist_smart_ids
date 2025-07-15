
import unittest
from aggregator.enrichment import get_whois_info

class TestEnrichment(unittest.TestCase):

    def test_get_whois_info(self):
        info = get_whois_info("8.8.8.8")
        self.assertIsNotNone(info)

if __name__ == '__main__':
    unittest.main()
