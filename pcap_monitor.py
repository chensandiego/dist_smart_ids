
import time
import os
from scapy.all import rdpcap
from detector import packet_handler

PCAP_DIR = "wireshark_pcapoutput"
PROCESSED_DIR = "processed_pcaps"

def process_pcap(file_path):
    print(f"📦 Processing PCAP file: {file_path}")
    packets = rdpcap(file_path)
    for pkt in packets:
        packet_handler(pkt)

def move_to_processed(file_path):
    try:
        os.rename(file_path, os.path.join(PROCESSED_DIR, os.path.basename(file_path)))
    except OSError as e:
        print(f"Error moving file: {e}")

def monitor_directory():
    print(f"👀 Monitoring directory for new PCAP files: {PCAP_DIR}")
    while True:
        for filename in os.listdir(PCAP_DIR):
            if filename.endswith(".pcap"):
                file_path = os.path.join(PCAP_DIR, filename)
                process_pcap(file_path)
                move_to_processed(file_path)
        time.sleep(5)
