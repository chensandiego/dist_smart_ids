import time
import logging
import os
import math
import json
from collections import defaultdict
from scapy.all import TCP, IP, SMB2_Header, SMB2_Create_Request, SMB2_Set_Info_Request, Ether
from typing import Dict, Any

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from config import KAFKA_HOST, KAFKA_TOPIC_PCAP, KAFKA_TOPIC_RANSOMWARE_ALERTS

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants for Ransomware Detection ---
TIME_WINDOW_SECONDS: int = 60
MAX_FILE_OPERATIONS: int = 100
MAX_FILE_RENAMES: int = 10
MAX_FILE_DELETES: int = 10
HIGH_ENTROPY_THRESHOLD: float = 3.5
SUSPICIOUS_EXTENSIONS = {'.locked', '.encrypted', '.crypto'}

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
    if not s:
        return 0.0
    entropy = 0
    for char_code in range(256):
        p_x = float(s.count(chr(char_code))) / len(s)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def create_kafka_producer():
    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_HOST,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        return producer
    except KafkaError as e:
        logging.error(f"Error creating Kafka producer: {e}")
        return None

def send_alert_to_kafka(producer: KafkaProducer, topic: str, alert_data: dict) -> None:
    try:
        producer.send(topic, value=alert_data)
        producer.flush()
        logging.info(f"[RANSOMWARE ALERT] Published to {topic}")
    except KafkaError as e:
        logging.error(f"Kafka error while publishing ransomware alert: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in send_alert_to_kafka: {e}", exc_info=True)

# --- SMB Command Monitoring ---
def monitor_smb_activity(pkt: Any, producer: KafkaProducer) -> None:
    detect_shadow_copy_deletion(pkt, producer)

    if not pkt.haslayer(TCP) or not pkt.haslayer(IP) or not pkt.haslayer(SMB2_Header):
        return

    if pkt[TCP].dport != 445 and pkt[TCP].sport != 445:
        return

    src_ip: str = pkt[IP].src
    current_time: float = time.time()

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

    smb_header = pkt[SMB2_Header]
    
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

    elif smb_header.Command == 0x12:  # DELETE
        SMB_ACTIVITY[src_ip]['deletes'] += 1

# --- Ransomware Behavior Detection ---
def detect_ransomware_behavior(producer: KafkaProducer) -> None:
    for ip, activity in list(SMB_ACTIVITY.items()):
        if time.time() - activity['timestamp'] > TIME_WINDOW_SECONDS:
            del SMB_ACTIVITY[ip]
            continue

        reasons = []
        
        if activity['operations'] > MAX_FILE_OPERATIONS:
            reasons.append(f"{activity['operations']} file operations")
        if activity['renames'] > MAX_FILE_RENAMES:
            reasons.append(f"{activity['renames']} renames")
        if activity['deletes'] > MAX_FILE_DELETES:
            reasons.append(f"{activity['deletes']} deletes")

        if activity['filename_entropy']:
            avg_entropy = sum(activity['filename_entropy']) / len(activity['filename_entropy'])
            if avg_entropy > HIGH_ENTROPY_THRESHOLD:
                reasons.append(f"average filename entropy of {avg_entropy:.2f}")

        suspicious_ext_count = sum(count for ext, count in activity['file_extensions'].items() if ext in SUSPICIOUS_EXTENSIONS)
        if suspicious_ext_count > 0:
            reasons.append(f"{suspicious_ext_count} suspicious file extensions")

        if activity['writes'] > 0 and activity['reads'] == 0:
            reasons.append("high number of writes without corresponding reads")

        if reasons:
            reason_str = f"Ransomware-like behavior detected from {ip}: {', '.join(reasons)} in the last {TIME_WINDOW_SECONDS} seconds."
            alert = {
                "reason": reason_str,
                "cve": "RANSOMWARE-BEHAVIOR-ENHANCED",
                "src_ip": ip
            }
            send_alert_to_kafka(producer, KAFKA_TOPIC_RANSOMWARE_ALERTS, alert)
            del SMB_ACTIVITY[ip]

def detect_shadow_copy_deletion(pkt: Any, producer: KafkaProducer) -> None:
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    try:
        payload = bytes(pkt[TCP].payload)
        if b'vssadmin' in payload and b'delete' in payload and b'shadows' in payload:
            src_ip = pkt[IP].src
            reason = f"Attempt to delete Volume Shadow Copies detected from {src_ip}. This is a strong indicator of a ransomware attack."
            alert = {
                "reason": reason,
                "cve": "RANSOMWARE-SHADOW-COPY-DELETION",
                "src_ip": src_ip
            }
            send_alert_to_kafka(producer, KAFKA_TOPIC_RANSOMWARE_ALERTS, alert)
    except Exception as e:
        logging.error(f"Error detecting shadow copy deletion: {e}")

def create_kafka_consumer(topic: str):
    try:
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=KAFKA_HOST,
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            group_id='ransomware-detector-group',
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
        return consumer
    except KafkaError as e:
        logging.error(f"Error creating Kafka consumer: {e}")
        return None

def main():
    consumer = create_kafka_consumer(KAFKA_TOPIC_PCAP)
    producer = create_kafka_producer()

    if not consumer or not producer:
        logging.error("Could not create Kafka consumer or producer. Exiting.")
        return

    logging.info(f"[*] Starting ransomware detector, consuming from {KAFKA_TOPIC_PCAP}")
    while True:
        for message in consumer:
            packet_data = message.value
            pkt = Ether(bytes.fromhex(packet_data['packet']))
            monitor_smb_activity(pkt, producer)
            detect_ransomware_behavior(producer)

if __name__ == '__main__':
    main()