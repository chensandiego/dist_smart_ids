import json
import time
import re
import os
import logging
from typing import Dict, Any, Optional, Iterator

from kafka import KafkaProducer
from kafka.errors import KafkaError

from config import KAFKA_HOST, KAFKA_TOPIC_SURICATA
from enrichment import get_abuseipdb_info, get_geolocation, get_service_name, get_passive_dns_info

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_cve_info(signature: str) -> Optional[str]:
    """
    Extracts CVE information from the alert signature using regex.
    """
    cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,7})")
    match = cve_pattern.search(signature)
    if match:
        return match.group(1)
    return None

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

def send_alert_to_kafka(producer: KafkaProducer, topic: str, alert_data: Dict[str, Any]) -> None:
    try:
        producer.send(topic, value=alert_data)
        producer.flush()
        logging.info(f"[Suricata Alert] Published to {topic}: {alert_data.get('alert', {}).get('signature', 'N/A')}")
    except KafkaError as e:
        logging.error(f"Kafka error while publishing Suricata alert: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in send_alert_to_kafka: {e}", exc_info=True)

def tail_file(filepath: str) -> Iterator[str]:
    if not os.path.exists(filepath):
        logging.error(f"File not found: {filepath}. Please ensure Suricata is writing to this path.")
        return

    with open(filepath, 'r') as f:
        # Go to the end of the file
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)  # Sleep briefly
                continue
            yield line

def main() -> None:
    EVE_JSON_PATH: str = "/var/log/suricata/eve.json"
    logging.info(f"[*] Starting Suricata EVE JSON parser, tailing {EVE_JSON_PATH}")
    
    producer = create_kafka_producer()
    if not producer:
        logging.error("Could not create Kafka producer. Exiting.")
        return

    for line in tail_file(EVE_JSON_PATH):
        try:
            event: Dict[str, Any] = json.loads(line.strip())
            if event.get("event_type") == "alert":
                # Extract CVE information
                signature: str = event.get("alert", {}).get("signature", "")
                cve_id: Optional[str] = extract_cve_info(signature)
                if cve_id:
                    event["cve"] = cve_id

                # Enrich Suricata alerts with AbuseIPDB info
                src_ip: Optional[str] = event.get("src_ip")
                dest_ip: Optional[str] = event.get("dest_ip")
                dest_port: Optional[int] = event.get("dest_port")

                if src_ip:
                    event["abuseipdb_src"] = get_abuseipdb_info(src_ip)
                    event["src_geolocation"] = get_geolocation(src_ip)
                    event["src_passive_dns"] = get_passive_dns_info(src_ip)
                if dest_ip:
                    event["abuseipdb_dst"] = get_abuseipdb_info(dest_ip)
                    event["dest_geolocation"] = get_geolocation(dest_ip)
                    event["dest_passive_dns"] = get_passive_dns_info(dest_ip)
                if dest_port:
                    event["dest_service"] = get_service_name(dest_port)

                sid: Optional[int] = event.get("alert", {}).get("sid")
                if sid in [2000001, 2000002]:  # Golden Ticket or Silver Ticket SIDs
                    handle_ad_attack_alert(event)
                
                send_alert_to_kafka(producer, KAFKA_TOPIC_SURICATA, event)
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from Suricata EVE log: {e} - Line: {line.strip()}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while processing Suricata EVE log: {e}", exc_info=True)

def handle_ad_attack_alert(alert_data: Dict[str, Any]) -> None:
    """
    Handles Golden Ticket and Silver Ticket alerts.
    """
    sid = alert_data.get("alert", {}).get("sid")
    msg = alert_data.get("alert", {}).get("signature")
    logging.info(f"Detected AD Attack Alert (SID: {sid}): {msg}")
    # Further processing for AD attack alerts can be added here,
    # e.g., extracting specific Kerberos fields, correlating with other data,
    # or sending to a dedicated AD security monitoring system.

if __name__ == "__main__":
    main()