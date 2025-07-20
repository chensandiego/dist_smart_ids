from scapy.all import IP
from sklearn.ensemble import IsolationForest
from joblib import load
import time
import json
import pika
from config import RABBITMQ_HOST, RABBITMQ_QUEUE
from enrichment import get_whois_info, get_abuseipdb_info
from behavior_model import behavior_model
from ransomware_detector import monitor_smb_activity, detect_ransomware_behavior

model = load("model/isolation_forest_model.joblib")
SIMILARITY_THRESHOLD = 0.5  # Define a threshold for similarity

LAST_RANSOMWARE_CHECK = time.time()
CHECK_INTERVAL = 10 # seconds

def extract_features(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        return [len(pkt), ip_layer.ttl, ip_layer.proto, ip_layer.len]
    return [0, 0, 0, 0]

def raise_alert(pkt, reason, cve=None):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src = pkt[IP].src if IP in pkt else "unknown"
    dst = pkt[IP].dst if IP in pkt else "unknown"

    whois_info = get_whois_info(src)
    abuseipdb_src_info = get_abuseipdb_info(src)
    abuseipdb_dst_info = get_abuseipdb_info(dst)

    alert = {
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
        connection.close()
        print(f"[ALERT] Published to {RABBITMQ_QUEUE}: {alert['reason']}")
    except pika.exceptions.AMQPError as e:
        print(f"RabbitMQ error: {e}")

def packet_handler(pkt):
    global LAST_RANSOMWARE_CHECK

    if IP not in pkt:
        return

    # Pass packet to ransomware detector
    monitor_smb_activity(pkt)

    # Periodically check for ransomware behavior
    current_time = time.time()
    if current_time - LAST_RANSOMWARE_CHECK > CHECK_INTERVAL:
        detect_ransomware_behavior()
        LAST_RANSOMWARE_CHECK = current_time

    # Behavior-based detection
    packet_content = bytes(pkt).decode(errors='ignore')
    similarity_score = behavior_model.get_similarity(packet_content)
    
    if similarity_score > SIMILARITY_THRESHOLD:
        reason = f"可疑行為偵測 (相似度: {similarity_score:.2f})"
        raise_alert(pkt, reason)
        return

    # Anomaly-based detection
    features = extract_features(pkt)
    prediction = model.predict([features])
    if prediction[0] == -1:
        raise_alert(pkt, "異常流量偵測")
