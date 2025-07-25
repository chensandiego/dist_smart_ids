from scapy.all import IP
from sklearn.ensemble import IsolationForest
from joblib import load
import time
import json
import pika
import logging
from typing import Dict, Any, Optional
import threading

from config import RABBITMQ_HOST, RABBITMQ_QUEUE
from enrichment import get_whois_info, get_abuseipdb_info
from behavior_model import behavior_model
from ransomware_detector import monitor_smb_activity, detect_ransomware_behavior
from email_scanner import scan_exchange_inbox

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Anomaly Detection Model ---
try:
    model: IsolationForest = load("model/isolation_forest_model.joblib")
    logging.info("Isolation Forest model loaded successfully.")
except FileNotFoundError:
    logging.error("Isolation Forest model file not found. Please ensure 'model/isolation_forest_model.joblib' exists.")
    model = None
exce_pt Exception as e:
    logging.error(f"Error loading Isolation Forest model: {e}", exc_info=True)
    model = None

SIMILARITY_THRESHOLD: float = 0.5

# --- Ransomware Detection ---
LAST_RANSOMWARE_CHECK: float = time.time()
CHECK_INTERVAL: int = 10 # seconds

# --- Email Scanning ---
EMAIL_SCAN_INTERVAL: int = 300 # 5 minutes

def run_email_scan_periodically():
    """Runs the email scanner in a separate thread at a regular interval."""
    while True:
        logging.info("Starting periodic email scan...")
        try:
            scan_exchange_inbox()
        except Exception as e:
            logging.error(f"An error occurred during the email scan: {e}", exc_info=True)
        logging.info(f"Email scan finished. Waiting {EMAIL_SCAN_INTERVAL} seconds for the next scan.")
        time.sleep(EMAIL_SCAN_INTERVAL)

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
    global LAST_RANSOMWARE_CHECK

    if IP not in pkt:
        return

    # Pass packet to ransomware detector
    monitor_smb_activity(pkt)

    # Periodically check for ransomware behavior
    current_time: float = time.time()
    if current_time - LAST_RANSOMWARE_CHECK > CHECK_INTERVAL:
        ransomware_alerts = detect_ransomware_behavior()
        for alert in ransomware_alerts:
            raise_alert(alert)
        LAST_RANSOMWARE_CHECK = current_time

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

    # Anomaly-based detection
    if model:
        features: list[Any] = extract_features(pkt)
        prediction: Any = model.predict([features])
        if prediction[0] == -1:
            alert = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "reason": "異常流量偵測",
                "packet": bytes(pkt).hex()
            }
            raise_alert(alert)

# --- Main Execution ---
if __name__ == "__main__":
    # Start the email scanner in a background thread
    email_thread = threading.Thread(target=run_email_scan_periodically, daemon=True)
    email_thread.start()
    logging.info("Email scanner thread started.")

    # The main thread will continue with its existing tasks (e.g., packet sniffing)
    # For demonstration, we'll just keep the main thread alive.
    # In your actual application, you would start your packet sniffing loop here.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
