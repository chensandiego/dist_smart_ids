import json
import logging
from typing import Dict, Any

from kafka import KafkaConsumer
from kafka.errors import KafkaError

from aggregator.config import KAFKA_HOST, KAFKA_TOPIC_SURICATA, RABBITMQ_HOST, RABBITMQ_QUEUE
from .enrichment import get_whois_info
from .behavior_model import behavior_model
from joblib import load
import pika

def extract_features(pkt):
    # Placeholder feature extraction
    # Replace with actual feature extraction logic
    if pkt.haslayer('IP'):
        src_ip = pkt['IP'].src
        dst_ip = pkt['IP'].dst
    else:
        src_ip = '0.0.0.0'
        dst_ip = '0.0.0.0'

    if pkt.haslayer('TCP'):
        src_port = pkt['TCP'].sport
        dst_port = pkt['TCP'].dport
    elif pkt.haslayer('UDP'):
        src_port = pkt['UDP'].sport
        dst_port = pkt['UDP'].dport
    else:
        src_port = 0
        dst_port = 0

    return [src_ip, dst_ip, src_port, dst_port]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

model = load("aggregator/model/isolation_forest_model.joblib")
SIMILARITY_THRESHOLD = 0.5  # Define a threshold for similarity

def create_kafka_consumer(topic: str):
    try:
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=KAFKA_HOST,
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            group_id='my-group',
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
        return consumer
    except KafkaError as e:
        logging.error(f"Error creating Kafka consumer: {e}")
        return None

def raise_alert(alert_data: Dict[str, Any], reason: str):
    alert_data['reason'] = reason
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
        logging.info(f"[ALERT] Published to {RABBITMQ_QUEUE}: {reason}")
    except pika.exceptions.AMQPError as e:
        logging.error(f"RabbitMQ error: {e}")

def process_suricata_alert(alert: Dict[str, Any]):
    # Behavior-based detection
    if 'alert' in alert and 'signature' in alert['alert']:
        signature = alert['alert']['signature']
        similarity_score = behavior_model.get_similarity(signature)
        if similarity_score > SIMILARITY_THRESHOLD:
            reason = f"可疑行為偵測 (相似度: {similarity_score:.2f})"
            raise_alert(alert, reason)

    # Anomaly-based detection (example using alert data)
    if 'src_ip' in alert and 'dest_ip' in alert:
        # This is a placeholder for more sophisticated anomaly detection
        # For now, we'll just flag all Suricata alerts as anomalies
        raise_alert(alert, "Suricata 警報：異常流量偵測")

def main():
    consumer = create_kafka_consumer(KAFKA_TOPIC_SURICATA)
    if not consumer:
        logging.error("Could not create Kafka consumer. Exiting.")
        return

    logging.info(f"[*] Starting Kafka consumer for topic {KAFKA_TOPIC_SURICATA}")
    for message in consumer:
        alert = message.value
        logging.info(f"Received Suricata alert: {alert.get('alert', {}).get('signature', 'N/A')}")
        process_suricata_alert(alert)

if __name__ == "__main__":
    main()