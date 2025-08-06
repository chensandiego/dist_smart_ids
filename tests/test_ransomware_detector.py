import unittest
from unittest.mock import patch, MagicMock
from scapy.all import IP, TCP, SMB2_Header, SMB2_Create_Request

from ransomware_detector import monitor_smb_activity, detect_ransomware_behavior, SMB_ACTIVITY

class TestRansomwareDetector(unittest.TestCase):

    def setUp(self):
        SMB_ACTIVITY.clear()
        self.mock_producer = MagicMock()

    @patch('ransomware_detector.send_alert_to_kafka')
    def test_high_entropy_detection(self, mock_send_alert):
        test_ip = "192.168.1.101"
        filename = "z5H8dKj9LpW3qXo7.txt"
        pkt = IP(src=test_ip) / TCP(dport=445) / SMB2_Header(Command=0x05) / SMB2_Create_Request(Name=filename)
        monitor_smb_activity(pkt, self.mock_producer)
        
        detect_ransomware_behavior(self.mock_producer)
        mock_send_alert.assert_called_once()

    @patch('ransomware_detector.send_alert_to_kafka')
    def test_suspicious_extension_detection(self, mock_send_alert):
        test_ip = "192.168.1.102"
        for ext in ['.locked', '.crypto']:
            filename = f"document{ext}"
            pkt = IP(src=test_ip) / TCP(dport=445) / SMB2_Header(Command=0x05) / SMB2_Create_Request(Name=filename)
            monitor_smb_activity(pkt, self.mock_producer)
        
        detect_ransomware_behavior(self.mock_producer)
        mock_send_alert.assert_called_once()

    @patch('ransomware_detector.send_alert_to_kafka')
    def test_high_write_ratio_detection(self, mock_send_alert):
        test_ip = "192.168.1.103"
        for _ in range(10):
            pkt = IP(src=test_ip) / TCP(dport=445) / SMB2_Header(Command=0x09) # WRITE
            monitor_smb_activity(pkt, self.mock_producer)
        
        detect_ransomware_behavior(self.mock_producer)
        mock_send_alert.assert_called_once()

    @patch('ransomware_detector.send_alert_to_kafka')
    def test_benign_traffic(self, mock_send_alert):
        test_ip = "192.168.1.104"
        # Simulate some normal traffic
        for i in range(5):
            pkt_read = IP(src=test_ip) / TCP(dport=445) / SMB2_Header(Command=0x08) / SMB2_Create_Request(Name="file.txt") # READ
            monitor_smb_activity(pkt_read, self.mock_producer)
            pkt_write = IP(src=test_ip) / TCP(dport=445) / SMB2_Header(Command=0x09) # WRITE
            monitor_smb_activity(pkt_write, self.mock_producer)

        detect_ransomware_behavior(self.mock_producer)
        mock_send_alert.assert_not_called()

if __name__ == '__main__':
    unittest.main()
