import unittest
from scapy.all import IP, TCP
from detector import extract_features, match_suricata_signature

class TestDetector(unittest.TestCase):

    def test_extract_features(self):
        pkt = IP(dst="8.8.8.8")/TCP()
        features = extract_features(pkt)
        self.assertEqual(len(features), 4)

    def test_match_suricata_signature(self):
        pkt = IP(dst="8.8.8.8")/TCP()/"GET /index.html HTTP/1.1\r\n\r\n"
        msg = match_suricata_signature(pkt)
        self.assertIsNone(msg)

if __name__ == '__main__':
    unittest.main()
