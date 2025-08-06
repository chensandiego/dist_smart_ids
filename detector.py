from scapy.all import IP, Ether
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from joblib import load
import time
import json
import pika
import logging
from typing import Dict, Any, Optional
import threading

from kafka import KafkaConsumer
from kafka.errors import KafkaError

from config import (
    RABBITMQ_HOST, RABBITMQ_QUEUE, KAFKA_HOST, KAFKA_TOPIC_PCAP,
    KAFKA_TOPIC_DNS_ALERTS, KAFKA_TOPIC_RANSOMWARE_ALERTS, KAFKA_TOPIC_EMAIL_ALERTS, KAFKA_TOPIC_SURICATA
)
from enrichment import get_whois_info, get_abuseipdb_info
from behavior_model import behavior_model

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Anomaly Detection Models ---
try:
    isolation_forest_model: IsolationForest = load("model/isolation_forest_model.joblib")
    logging.info("Isolation Forest model loaded successfully.")
except FileNotFoundError:
    logging.error("Isolation Forest model file not found. Please ensure 'model/isolation_forest_model.joblib' exists.")
    isolation_forest_model = None
except Exception as e:
    logging.error(f"Error loading Isolation Forest model: {e}", exc_info=True)
    isolation_forest_model = None

from config import DBSCAN_EPS, DBSCAN_MIN_SAMPLES
dbscan_model: DBSCAN = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES)
logging.info(f"DBSCAN model initialized with eps={DBSCAN_EPS}, min_samples={DBSCAN_MIN_SAMPLES}.")

# Store recent features for DBSCAN
recent_features = []
MAX_RECENT_FEATURES = 1000 # Adjust as needed

SIMILARITY_THRESHOLD: float = 0.5

# --- Alerting ---
def raise_alert(alert_details: Dict[str, Any]) -> None:
    """Publishes a JSON alert to the RabbitMQ queue."""
    connection = None
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
        channel.basic_publish(
            exchange='',
            routing_key=RABBITMQ_QUEUE,
            body=json.dumps(alert_details),
            properties=pika.BasicProperties(
                delivery_mode=2,  # Make message persistent
            )
        )
        logging.info(f"[ALERT] Published to {RABBITMQ_QUEUE}: {alert_details.get('reason', 'No reason provided')}")
    except pika.exceptions.AMQPError as e:
        logging.error(f"RabbitMQ error while publishing alert: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in raise_alert: {e}", exc_info=True)
    finally:
        if connection and connection.is_open:
            connection.close()

# --- Packet Analysis ---
def extract_features(pkt: Any) -> list[Any]:
    if IP in pkt:
        ip_layer = pkt[IP]
        return [len(pkt), ip_layer.ttl, ip_layer.proto, ip_layer.len]
    return [0, 0, 0, 0]

def packet_handler(pkt: Any) -> None:
    if IP not in pkt:
        return

    # Behavior-based detection
    packet_content: str = bytes(pkt).decode(errors='ignore')
    similarity_score: float = behavior_model.get_similarity(packet_content)
    
    if similarity_score > SIMILARITY_THRESHOLD:
        reason: str = f"可疑行為偵測 (相似度: {similarity_score:.2f})"
        alert = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "reason": reason,
            "packet": bytes(pkt).hex()
        }
        raise_alert(alert)
        return

    # Anomaly-based detection (Isolation Forest)
    features: list[Any] = extract_features(pkt)
    if isolation_forest_model:
        prediction_if: Any = isolation_forest_model.predict([features])
        if prediction_if[0] == -1:
            alert = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "reason": "異常流量偵測 (Isolation Forest)",
                "packet": bytes(pkt).hex()
            }
            raise_alert(alert)

    # Anomaly-based detection (DBSCAN)
    recent_features.append(features)
    if len(recent_features) > MAX_RECENT_FEATURES:
        recent_features.pop(0) # Keep the list size bounded

    if len(recent_features) >= DBSCAN_MIN_SAMPLES:
        try:
            dbscan_model.fit(recent_features)
            prediction_dbscan = dbscan_model.fit_predict([features])
            if prediction_dbscan[0] == -1:
                alert = {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "reason": "異常流量偵測 (DBSCAN)",
                    "packet": bytes(pkt).hex()
                }
                raise_alert(alert)
        except Exception as e:
            logging.error(f"Error fitting or predicting with DBSCAN: {e}", exc_info=True)

def create_kafka_consumer(topic: str, group_id: str):
    try:
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=KAFKA_HOST,
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            group_id=group_id,
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
        return consumer
    except KafkaError as e:
        logging.error(f"Error creating Kafka consumer for topic {topic}: {e}")
        return None

def consume_alerts(topic: str, group_id: str):
    consumer = create_kafka_consumer(topic, group_id)
    if not consumer:
        return

    logging.info(f"[*] Starting Kafka consumer for topic {topic}")
    for message in consumer:
        alert = message.value
        logging.info(f"Received alert from {topic}: {alert.get('reason', 'N/A')}")
        raise_alert(alert)

# --- Main Execution ---
if __name__ == "__main__":
    # Start consumers in background threads
    topics = {
        KAFKA_TOPIC_SURICATA: "detector-suricata-group",
        KAFKA_TOPIC_DNS_ALERTS: "detector-dns-group",
        KAFKA_TOPIC_RANSOMWARE_ALERTS: "detector-ransomware-group",
        KAFKA_TOPIC_EMAIL_ALERTS: "detector-email-group"
    }

    for topic, group_id in topics.items():
        thread = threading.Thread(target=consume_alerts, args=(topic, group_id), daemon=True)
        thread.start()

    pcap_consumer = create_kafka_consumer(KAFKA_TOPIC_PCAP, "detector-pcap-group")
    if not pcap_consumer:
        logging.error("Could not create Kafka consumer for PCAP data. Exiting.")
    else:
        logging.info(f"[*] Starting Kafka consumer for topic {KAFKA_TOPIC_PCAP}")
        for message in pcap_consumer:
            packet_data = message.value
            pkt = Ether(bytes.fromhex(packet_data['packet']))
            packet_handler(pkt)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
