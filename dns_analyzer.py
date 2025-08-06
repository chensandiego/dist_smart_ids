import logging
import json
from scapy.all import DNS, DNSQR, DNSRR, IP, Ether

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

from config import KAFKA_HOST, KAFKA_TOPIC_PCAP, KAFKA_TOPIC_DNS_ALERTS

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Placeholder for a real malicious domain blocklist
MALICIOUS_DOMAINS = {
    "evil-domain.com",
    "malware-distributor.net",
    "phishing-site.org",
}

# Threshold for query name length to detect potential DNS tunneling
LONG_QUERY_THRESHOLD = 100

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
        logging.info(f"[DNS ALERT] Published to {topic}")
    except KafkaError as e:
        logging.error(f"Kafka error while publishing DNS alert: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in send_alert_to_kafka: {e}", exc_info=True)

def analyze_dns_packet(pkt, producer):
    """
    Analyzes a DNS packet for suspicious activity.
    
    Sends alerts to Kafka for any suspicious findings.
    """
    if pkt.haslayer(DNS):
        dns_layer = pkt[DNS]
        
        # Analyze DNS Query Record
        if dns_layer.qr == 0 and dns_layer.qd:  # This is a query
            query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
            
            # Check for long query names (potential DNS tunneling)
            if len(query_name) > LONG_QUERY_THRESHOLD:
                alert = {
                    "reason": "Potential DNS Tunneling (Long Query Name)",
                    "details": f"Query name '{query_name}' exceeds {LONG_QUERY_THRESHOLD} characters.",
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                }
                send_alert_to_kafka(producer, KAFKA_TOPIC_DNS_ALERTS, alert)

            # Check if the queried domain is in the malicious list
            if query_name in MALICIOUS_DOMAINS:
                alert = {
                    "reason": "DNS Query to Malicious Domain",
                    "details": f"DNS query for known malicious domain: {query_name}",
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                }
                send_alert_to_kafka(producer, KAFKA_TOPIC_DNS_ALERTS, alert)

def create_kafka_consumer(topic: str):
    try:
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=KAFKA_HOST,
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            group_id='dns-analyzer-group',
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

    logging.info(f"[*] Starting DNS analyzer, consuming from {KAFKA_TOPIC_PCAP}")
    for message in consumer:
        packet_data = message.value
        pkt = Ether(bytes.fromhex(packet_data['packet']))
        analyze_dns_packet(pkt, producer)

if __name__ == "__main__":
    main()