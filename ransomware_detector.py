
import time
import logging
from collections import defaultdict
from scapy.all import TCP, IP
from typing import Dict, Any

from detector import raise_alert

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants for Ransomware Detection ---

# Time window in seconds to track SMB activity for each source IP
TIME_WINDOW_SECONDS: int = 60

# Thresholds for suspicious activity within the time window
# These values may need tuning based on normal network activity
MAX_FILE_OPERATIONS: int = 100  # Total file operations (read, write, create)
MAX_FILE_RENAMES: int = 10      # Number of file rename operations
MAX_FILE_DELETES: int = 10      # Number of file delete operations

# --- In-Memory Store for SMB Activity ---

# This dictionary stores activity counters for each source IP.
# Structure: { 'ip_address': { 'timestamp': float, 'operations': int, 'renames': int, 'deletes': int } }
SMB_ACTIVITY: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
    'timestamp': 0.0,
    'operations': 0,
    'renames': 0,
    'deletes': 0
})

# --- SMB Command Monitoring ---

def monitor_smb_activity(pkt: Any) -> None:
    """
    Inspects a packet for SMB commands and updates activity counters if found.
    """
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    # Check for SMB traffic (typically on port 445)
    if pkt[TCP].dport != 445 and pkt[TCP].sport != 445:
        return

    src_ip: str = pkt[IP].src
    current_time: float = time.time()

    # Reset counters if the time window has expired
    if current_time - SMB_ACTIVITY[src_ip]['timestamp'] > TIME_WINDOW_SECONDS:
        SMB_ACTIVITY[src_ip] = {
            'timestamp': current_time,
            'operations': 0,
            'renames': 0,
            'deletes': 0
        }

    # --- SMB Command Analysis ---
    # Convert the raw payload to a string to search for command names.
    # This is a simplified approach; a more robust solution would use a full SMB parser.
    try:
        payload: str = bytes(pkt[TCP].payload).decode(errors='ignore')
    except Exception as e:
        logging.warning(f"Could not decode TCP payload for SMB activity monitoring: {e}")
        return

    # Check for common SMB commands related to file operations
    if 'SMB2' in payload:
        if 'CREATE' in payload or 'WRITE' in payload or 'READ' in payload:
            SMB_ACTIVITY[src_ip]['operations'] += 1
        if 'SET_INFO' in payload:  # SET_INFO is often used for renames
            SMB_ACTIVITY[src_ip]['renames'] += 1
        if 'DELETE' in payload:
            SMB_ACTIVITY[src_ip]['deletes'] += 1

# --- Ransomware Behavior Detection ---

def detect_ransomware_behavior() -> None:
    """
    Analyzes the collected SMB activity and raises an alert if it matches
    ransomware-like patterns (e.g., high volume of file renames or deletes).
    """
    for ip, activity in list(SMB_ACTIVITY.items()):
        # Check if the activity is within the current time window
        if time.time() - activity['timestamp'] > TIME_WINDOW_SECONDS:
            del SMB_ACTIVITY[ip]  # Clean up old entries
            continue

        # --- Alerting Logic ---
        # Raise an alert if any of the thresholds are exceeded
        if (activity['operations'] > MAX_FILE_OPERATIONS or
                activity['renames'] > MAX_FILE_RENAMES or
                activity['deletes'] > MAX_FILE_DELETES):
            
            reason: str = (
                f"Ransomware-like behavior detected from {ip}: "
                f"{activity['operations']} file operations, "
                f"{activity['renames']} renames, "
                f"{activity['deletes']} deletes in the last {TIME_WINDOW_SECONDS} seconds."
            )
            
            # Create a synthetic packet for the alert, as this is a summary of many packets
            # The destination IP can be set to a broadcast or a known file server IP if available
            synthetic_pkt: IP = IP(src=ip, dst="255.255.255.255")
            
            logging.warning(f"[ALERT] {reason}")
            raise_alert(synthetic_pkt, reason, cve="RANSOMWARE-BEHAVIOR")
            
            # Reset the counters for this IP to avoid repeated alerts for the same activity
            del SMB_ACTIVITY[ip]

if __name__ == '__main__':
    # This is for standalone testing of the ransomware detector.
    # In the full system, these functions will be called from other modules.
    logging.info("Ransomware detector module is running in standalone test mode.")
    
    # Example: Simulate a burst of file renames from a single IP
    test_ip: str = "192.168.1.100"
    for i in range(MAX_FILE_RENAMES + 1):
        # Create a dummy packet for the simulation
        pkt: Any = IP(src=test_ip) / TCP(dport=445) / "SMB2...SET_INFO..."
        monitor_smb_activity(pkt)
    
    # Check for alerts
    detect_ransomware_behavior()
