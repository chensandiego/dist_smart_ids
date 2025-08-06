
import unittest
from unittest.mock import MagicMock, patch
from scapy.all import IP, UDP, DNS, DNSQR
from dns_analyzer import analyze_dns_packet, MALICIOUS_DOMAINS

class TestDnsAnalyzer(unittest.TestCase):

    def setUp(self):
        self.mock_producer = MagicMock()

    @patch('dns_analyzer.send_alert_to_kafka')
    def test_long_query_name(self, mock_send_alert):
        """Test detection of long DNS query names (potential DNS tunneling)."""
        long_name = 'a' * 101 + '.com'
        pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=long_name))
        
        analyze_dns_packet(pkt, self.mock_producer)
        
        mock_send_alert.assert_called_once()
        call_args = mock_send_alert.call_args[0]
        self.assertEqual(call_args[2]["reason"], "Potential DNS Tunneling (Long Query Name)")

    @patch('dns_analyzer.send_alert_to_kafka')
    def test_malicious_domain_query(self, mock_send_alert):
        """Test detection of DNS queries to known malicious domains."""
        malicious_domain = list(MALICIOUS_DOMAINS)[0]
        pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=malicious_domain))
        
        analyze_dns_packet(pkt, self.mock_producer)
        
        mock_send_alert.assert_called_once()
        call_args = mock_send_alert.call_args[0]
        self.assertEqual(call_args[2]["reason"], "DNS Query to Malicious Domain")

    @patch('dns_analyzer.send_alert_to_kafka')
    def test_normal_dns_query(self, mock_send_alert):
        """Test a normal DNS query that should not trigger any alerts."""
        pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
        
        analyze_dns_packet(pkt, self.mock_producer)
        
        mock_send_alert.assert_not_called()

if __name__ == '__main__':
    unittest.main()
