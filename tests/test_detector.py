import unittest
from scapy.all import IP, TCP
import unittest
from scapy.all import IP, TCP
from aggregator.detector import extract_features

class TestDetector(unittest.TestCase):

    def test_extract_features(self):
        pkt = IP(dst="8.8.8.8")/TCP()
        features = extract_features(pkt)
        self.assertEqual(len(features), 4)

if __name__ == '__main__':
    unittest.main()
