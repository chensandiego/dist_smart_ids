
import time
import logging
import os
import math
from collections import defaultdict
from scapy.all import TCP, IP, SMB2_Header, SMB2_Create_Request, SMB2_Set_Info_Request
from typing import Dict, Any



logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants for Ransomware Detection ---

# Time window in seconds to track SMB activity for each source IP
TIME_WINDOW_SECONDS: int = 60

# Thresholds for suspicious activity
MAX_FILE_OPERATIONS: int = 100
MAX_FILE_RENAMES: int = 10
MAX_FILE_DELETES: int = 10
HIGH_ENTROPY_THRESHOLD: float = 3.5
SUSPICIOUS_EXTENSIONS = {'.locked', '.encrypted', '.crypto'} # Add more known ransomware extensions

# --- In-Memory Store for SMB Activity ---

SMB_ACTIVITY: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
    'timestamp': 0.0,
    'operations': 0,
    'renames': 0,
    'deletes': 0,
    'writes': 0,
    'reads': 0,
    'file_extensions': defaultdict(int),
    'filename_entropy': []
})

# --- Helper Functions ---

def calculate_entropy(s: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not s:
        return 0.0
    entropy = 0
    for char_code in range(256):
        p_x = float(s.count(chr(char_code))) / len(s)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

# --- SMB Command Monitoring ---

def monitor_smb_activity(pkt: Any) -> None:
    """
    Inspects a packet for SMB commands and updates activity counters if found.
    This version uses Scapy for more reliable SMB parsing and feature extraction.
    """
    # Detect shadow copy deletion attempts first, as this is a high-priority indicator
    detect_shadow_copy_deletion(pkt)

    if not pkt.haslayer(TCP) or not pkt.haslayer(IP) or not pkt.haslayer(SMB2_Header):
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
            'deletes': 0,
            'writes': 0,
            'reads': 0,
            'file_extensions': defaultdict(int),
            'filename_entropy': []
        }

    # --- SMB Command Analysis with Scapy ---
    smb_header = pkt[SMB2_Header]
    
    # Track file operations
    if smb_header.Command == 0x05:  # CREATE
        SMB_ACTIVITY[src_ip]['operations'] += 1
        if pkt.haslayer(SMB2_Create_Request):
            filename = pkt[SMB2_Create_Request].Name
            SMB_ACTIVITY[src_ip]['filename_entropy'].append(calculate_entropy(filename))
            ext = os.path.splitext(filename)[1]
            if ext:
                SMB_ACTIVITY[src_ip]['file_extensions'][ext.lower()] += 1

    elif smb_header.Command == 0x09:  # WRITE
        SMB_ACTIVITY[src_ip]['writes'] += 1
        SMB_ACTIVITY[src_ip]['operations'] += 1
        
    elif smb_header.Command == 0x08:  # READ
        SMB_ACTIVITY[src_ip]['reads'] += 1
        SMB_ACTIVITY[src_ip]['operations'] += 1

    elif smb_header.Command == 0x0E:  # SET_INFO (often used for renames)
        SMB_ACTIVITY[src_ip]['renames'] += 1
        if pkt.haslayer(SMB2_Set_Info_Request) and pkt[SMB2_Set_Info_Request].FileInformationClass == 13: # Rename operation
            if hasattr(pkt[SMB2_Set_Info_Request], 'Buffer') and pkt[SMB2_Set_Info_Request].Buffer:
                # The new filename is in the buffer for rename requests
                # This requires a more complex parsing of the buffer which can be added later
                pass

    elif smb_header.Command == 0x12:  # DELETE (not a standard command, but for illustration)
        # Note: SMB delete is handled via SET_INFO with a specific flag.
        # This is a simplified representation.
        SMB_ACTIVITY[src_ip]['deletes'] += 1

# --- Ransomware Behavior Detection ---

def detect_ransomware_behavior() -> None:
    """
    Analyzes the collected SMB activity for ransomware-like patterns using enhanced features.
    """
    for ip, activity in list(SMB_ACTIVITY.items()):
        if time.time() - activity['timestamp'] > TIME_WINDOW_SECONDS:
            del SMB_ACTIVITY[ip]
            continue

        # --- Enhanced Alerting Logic ---
        reasons = []
        
        # 1. High volume of file operations
        if activity['operations'] > MAX_FILE_OPERATIONS:
            reasons.append(f"{activity['operations']} file operations")
        if activity['renames'] > MAX_FILE_RENAMES:
            reasons.append(f"{activity['renames']} renames")
        if activity['deletes'] > MAX_FILE_DELETES:
            reasons.append(f"{activity['deletes']} deletes")

        # 2. High filename entropy
        if activity['filename_entropy']:
            avg_entropy = sum(activity['filename_entropy']) / len(activity['filename_entropy'])
            if avg_entropy > HIGH_ENTROPY_THRESHOLD:
                reasons.append(f"average filename entropy of {avg_entropy:.2f}")

        # 3. Suspicious file extensions
        suspicious_ext_count = sum(count for ext, count in activity['file_extensions'].items() if ext in SUSPICIOUS_EXTENSIONS)
        if suspicious_ext_count > 0:
            reasons.append(f"{suspicious_ext_count} suspicious file extensions")

        # 4. Imbalanced Read/Write Ratio
        if activity['writes'] > 0 and activity['reads'] == 0:
            reasons.append("high number of writes without corresponding reads")

        if reasons:
            reason_str = f"Ransomware-like behavior detected from {ip}: {', '.join(reasons)} in the last {TIME_WINDOW_SECONDS} seconds."
            synthetic_pkt: IP = IP(src=ip, dst="255.255.255.255")
            logging.warning(f"[ALERT] {reason_str}")
            from detector import raise_alert
            raise_alert(synthetic_pkt, reason_str, cve="RANSOMWARE-BEHAVIOR-ENHANCED")
            del SMB_ACTIVITY[ip]

def detect_shadow_copy_deletion(pkt: Any) -> None:
    """
    Detects attempts to delete Volume Shadow Copies, a common ransomware tactic.
    """
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    try:
        payload = bytes(pkt[TCP].payload)
        # Look for the vssadmin command to delete shadows
        if b'vssadmin' in payload and b'delete' in payload and b'shadows' in payload:
            src_ip = pkt[IP].src
            reason = f"Attempt to delete Volume Shadow Copies detected from {src_ip}. This is a strong indicator of a ransomware attack."
            logging.warning(f"[ALERT] {reason}")
            from detector import raise_alert
            raise_alert(pkt, reason, cve="RANSOMWARE-SHADOW-COPY-DELETION")
    except Exception as e:
        logging.error(f"Error detecting shadow copy deletion: {e}")

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
