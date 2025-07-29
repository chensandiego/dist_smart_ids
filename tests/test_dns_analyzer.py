
import unittest
from scapy.all import IP, UDP, DNS, DNSQR
from dns_analyzer import analyze_dns_packet, MALICIOUS_DOMAINS

class TestDnsAnalyzer(unittest.TestCase):

    def test_long_query_name(self):
        """Test detection of long DNS query names (potential DNS tunneling)."""
        long_name = 'a' * 101 + '.com'
        pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=long_name))
        
        alerts = analyze_dns_packet(pkt)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["reason"], "Potential DNS Tunneling (Long Query Name)")

    def test_malicious_domain_query(self):
        """Test detection of DNS queries to known malicious domains."""
        malicious_domain = list(MALICIOUS_DOMAINS)[0]
        pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=malicious_domain))
        
        alerts = analyze_dns_packet(pkt)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["reason"], "DNS Query to Malicious Domain")

    def test_normal_dns_query(self):
        """Test a normal DNS query that should not trigger any alerts."""
        pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
        
        alerts = analyze_dns_packet(pkt)
        
        self.assertEqual(len(alerts), 0)

if __name__ == '__main__':
    unittest.main()
