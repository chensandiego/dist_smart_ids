from scapy.all import IP
from sklearn.ensemble import IsolationForest
from joblib import load
import time
import json
import pika
import logging
from typing import Dict, Any, Optional

from config import RABBITMQ_HOST, RABBITMQ_QUEUE
from enrichment import get_whois_info, get_abuseipdb_info
from behavior_model import behavior_model
from ransomware_detector import monitor_smb_activity, detect_ransomware_behavior

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    model: IsolationForest = load("model/isolation_forest_model.joblib")
    logging.info("Isolation Forest model loaded successfully.")
except FileNotFoundError:
    logging.error("Isolation Forest model file not found. Please ensure 'model/isolation_forest_model.joblib' exists.")
    model = None # type: ignore
except Exception as e:
    logging.error(f"Error loading Isolation Forest model: {e}", exc_info=True)
    model = None # type: ignore

SIMILARITY_THRESHOLD: float = 0.5  # Define a threshold for similarity

LAST_RANSOMWARE_CHECK: float = time.time()
CHECK_INTERVAL: int = 10 # seconds

def extract_features(pkt: Any) -> list[Any]:
    if IP in pkt:
        ip_layer = pkt[IP]
        return [len(pkt), ip_layer.ttl, ip_layer.proto, ip_layer.len]
    return [0, 0, 0, 0]

def raise_alert(pkt: Any, reason: str, cve: Optional[str] = None) -> None:
    timestamp: str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src: str = pkt[IP].src if IP in pkt else "unknown"
    dst: str = pkt[IP].dst if IP in pkt else "unknown"

    whois_info: Optional[Any] = get_whois_info(src)
    abuseipdb_src_info: Optional[Dict[str, Any]] = get_abuseipdb_info(src)
    abuseipdb_dst_info: Optional[Dict[str, Any]] = get_abuseipdb_info(dst)

    alert: Dict[str, Any] = {
        "time": timestamp,
        "src": src,
        "dst": dst,
        "reason": reason,
        "whois": whois_info,
        "abuseipdb_src": abuseipdb_src_info,
        "abuseipdb_dst": abuseipdb_dst_info,
        "packet": bytes(pkt).hex(),  # Serialize packet for the queue
        "cve": cve
    }

    connection = None
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
        channel.basic_publish(
            exchange='',
            routing_key=RABBITMQ_QUEUE,
            body=json.dumps(alert),
            properties=pika.BasicProperties(
                delivery_mode=2,  # Make message persistent
            )
        )
        logging.info(f"[ALERT] Published to {RABBITMQ_QUEUE}: {alert.get('reason', 'No reason provided')}")
    except pika.exceptions.AMQPError as e:
        logging.error(f"RabbitMQ error while publishing alert: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in raise_alert: {e}", exc_info=True)
    finally:
        if connection and connection.is_open:
            connection.close()

def packet_handler(pkt: Any) -> None:
    global LAST_RANSOMWARE_CHECK

    if IP not in pkt:
        return

    # Pass packet to ransomware detector
    monitor_smb_activity(pkt)

    # Periodically check for ransomware behavior
    current_time: float = time.time()
    if current_time - LAST_RANSOMWARE_CHECK > CHECK_INTERVAL:
        detect_ransomware_behavior()
        LAST_RANSOMWARE_CHECK = current_time

    # Behavior-based detection
    packet_content: str = bytes(pkt).decode(errors='ignore')
    similarity_score: float = behavior_model.get_similarity(packet_content)
    
    if similarity_score > SIMILARITY_THRESHOLD:
        reason: str = f"可疑行為偵測 (相似度: {similarity_score:.2f})"
        raise_alert(pkt, reason)
        return

    # Anomaly-based detection
    if model:
        features: list[Any] = extract_features(pkt)
        prediction: Any = model.predict([features])
        if prediction[0] == -1:
            raise_alert(pkt, "異常流量偵測")
    else:
        logging.warning("Anomaly detection model not loaded. Skipping anomaly detection.")
