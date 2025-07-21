
import time
import os
import logging
from scapy.all import rdpcap, Packet
from typing import NoReturn

from detector import packet_handler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PCAP_DIR: str = "wireshark_pcapoutput"
PROCESSED_DIR: str = "processed_pcaps"

def process_pcap(file_path: str) -> None:
    logging.info(f"📦 Processing PCAP file: {file_path}")
    try:
        packets = rdpcap(file_path)
        for pkt in packets:
            packet_handler(pkt)
        logging.info(f"Successfully processed PCAP file: {file_path}")
    except Exception as e:
        logging.error(f"Error processing PCAP file {file_path}: {e}", exc_info=True)

def move_to_processed(file_path: str) -> None:
    try:
        os.makedirs(PROCESSED_DIR, exist_ok=True)
        destination_path = os.path.join(PROCESSED_DIR, os.path.basename(file_path))
        os.rename(file_path, destination_path)
        logging.info(f"Moved {file_path} to {destination_path}")
    except OSError as e:
        logging.error(f"Error moving file {file_path} to processed directory: {e}")
    except Exception as e:
        logging.error(f"Unexpected error moving file {file_path}: {e}", exc_info=True)

def monitor_directory() -> NoReturn:
    logging.info(f"👀 Monitoring directory for new PCAP files: {PCAP_DIR}")
    os.makedirs(PCAP_DIR, exist_ok=True) # Ensure PCAP_DIR exists
    os.makedirs(PROCESSED_DIR, exist_ok=True) # Ensure PROCESSED_DIR exists

    while True:
        try:
            for filename in os.listdir(PCAP_DIR):
                if filename.endswith(".pcap"):
                    file_path = os.path.join(PCAP_DIR, filename)
                    process_pcap(file_path)
                    move_to_processed(file_path)
        except FileNotFoundError:
            logging.error(f"Monitoring directory {PCAP_DIR} not found. Please create it.")
        except Exception as e:
            logging.error(f"Error during directory monitoring: {e}", exc_info=True)
        time.sleep(5)

if __name__ == "__main__":
    monitor_directory()
