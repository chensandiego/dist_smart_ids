
import logging
from scapy.all import DNS, DNSQR, DNSRR, IP

# Placeholder for a real malicious domain blocklist
# In a real-world scenario, this would be populated from a threat intelligence feed.
MALICIOUS_DOMAINS = {
    "evil-domain.com",
    "malware-distributor.net",
    "phishing-site.org",
}

# Threshold for query name length to detect potential DNS tunneling
LONG_QUERY_THRESHOLD = 100

def analyze_dns_packet(pkt):
    """
    Analyzes a DNS packet for suspicious activity.
    
    Returns a list of alert dictionaries for any suspicious findings.
    """
    alerts = []
    if pkt.haslayer(DNS):
        dns_layer = pkt[DNS]
        
        # Analyze DNS Query Record
        if dns_layer.qr == 0 and dns_layer.qd:  # This is a query
            query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
            
            # Check for long query names (potential DNS tunneling)
            if len(query_name) > LONG_QUERY_THRESHOLD:
                alerts.append({
                    "reason": "Potential DNS Tunneling (Long Query Name)",
                    "details": f"Query name '{query_name}' exceeds {LONG_QUERY_THRESHOLD} characters.",
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                })

            # Check if the queried domain is in the malicious list
            if query_name in MALICIOUS_DOMAINS:
                alerts.append({
                    "reason": "DNS Query to Malicious Domain",
                    "details": f"DNS query for known malicious domain: {query_name}",
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                })

    return alerts
