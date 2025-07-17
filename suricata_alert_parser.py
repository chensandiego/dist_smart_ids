import json
import time
import pika
import re
from config import RABBITMQ_HOST, RABBITMQ_QUEUE
import os
from enrichment import get_abuseipdb_info, get_geolocation, get_service_name, get_passive_dns_info

def extract_cve_info(signature):
    """
    Extracts CVE information from the alert signature using regex.
    """
    cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,7})")
    match = cve_pattern.search(signature)
    if match:
        return match.group(1)
    return None

def send_alert_to_rabbitmq(alert_data):
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
        channel.basic_publish(
            exchange='',
            routing_key=RABBITMQ_QUEUE,
            body=json.dumps(alert_data),
            properties=pika.BasicProperties(
                delivery_mode=2,  # Make message persistent
            )
        )
        connection.close()
        print(f"[Suricata Alert] Published to {RABBITMQ_QUEUE}: {alert_data.get('alert', {}).get('signature', 'N/A')}")
    except pika.exceptions.AMQPError as e:
        print(f"RabbitMQ error: {e}")

def tail_file(filepath):
    with open(filepath, 'r') as f:
        # Go to the end of the file
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)  # Sleep briefly
                continue
            yield line

def main():
    EVE_JSON_PATH = "/var/log/suricata/eve.json"
    print(f"[*] Starting Suricata EVE JSON parser, tailing {EVE_JSON_PATH}")
    for line in tail_file(EVE_JSON_PATH):
        try:
            event = json.loads(line.strip())
            if event.get("event_type") == "alert":
                # Extract CVE information
                signature = event.get("alert", {}).get("signature", "")
                cve_id = extract_cve_info(signature)
                if cve_id:
                    event["cve"] = cve_id

                # Enrich Suricata alerts with AbuseIPDB info
                src_ip = event.get("src_ip")
                dest_ip = event.get("dest_ip")
                dest_port = event.get("dest_port")

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

                send_alert_to_rabbitmq(event)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e} - Line: {line.strip()}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()