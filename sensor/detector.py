from scapy.all import IP
from sklearn.ensemble import IsolationForest
from joblib import load
import time
import json
import pika
from config import RABBITMQ_HOST, RABBITMQ_QUEUE
import os

print("[Detector] Attempting to import enrichment and behavior_model...")
from enrichment import get_whois_info, get_abuseipdb_info, get_geolocation, get_service_name
from behavior_model import behavior_model
print("[Detector] Successfully imported enrichment and behavior_model.")

MODEL_PATH = "/app/model/isolation_forest_model.joblib"

print(f"[Detector] Attempting to load Isolation Forest model from: {MODEL_PATH}")
try:
    model = load(MODEL_PATH)
    print("[Detector] Successfully loaded Isolation Forest model.")
except FileNotFoundError:
    print(f"[Detector ERROR] Isolation Forest model not found at {MODEL_PATH}. Please ensure it exists.")
    model = None # Handle case where model is not found
except Exception as e:
    print(f"[Detector ERROR] Error loading Isolation Forest model: {e}")
    model = None

SIMILARITY_THRESHOLD = 0.5  # Define a threshold for similarity

def extract_features(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        # Ensure features are numeric and consistent
        return [float(len(pkt)), float(ip_layer.ttl), float(ip_layer.proto), float(ip_layer.len)]
    return [0.0, 0.0, 0.0, 0.0]

def raise_alert(pkt, reason):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src = pkt[IP].src if IP in pkt else "unknown"
    dst = pkt[IP].dst if IP in pkt else "unknown"

    print(f"[Detector] Raising alert for {src} -> {dst}: {reason}")

    whois_info = get_whois_info(src)
    abuseipdb_src_info = get_abuseipdb_info(src)
    abuseipdb_dst_info = get_abuseipdb_info(dst)
    
    # Add geolocation and service name for more context
    src_geolocation = get_geolocation(src)
    dst_geolocation = get_geolocation(dst)
    
    src_port = pkt.sport if hasattr(pkt, 'sport') else None
    dst_port = pkt.dport if hasattr(pkt, 'dport') else None
    src_service = get_service_name(src_port) if src_port else "N/A"
    dst_service = get_service_name(dst_port) if dst_port else "N/A"

    alert = {
        "time": timestamp,
        "src": src,
        "dst": dst,
        "reason": reason,
        "whois": str(whois_info), # Convert Whois object to string for serialization
        "abuseipdb_src": abuseipdb_src_info,
        "abuseipdb_dst": abuseipdb_dst_info,
        "src_geolocation": src_geolocation,
        "dst_geolocation": dst_geolocation,
        "src_port": src_port,
        "dst_port": dst_port,
        "src_service": src_service,
        "dst_service": dst_service,
        "packet": bytes(pkt).hex()  # Serialize packet for the queue
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
        print(f"[Detector ERROR] RabbitMQ error: {e}")
    except Exception as e:
        print(f"[Detector ERROR] Error publishing alert: {e}")

def packet_handler(pkt):
    if IP not in pkt:
        return

    print(f"[Detector] Processing packet from {pkt[IP].src} to {pkt[IP].dst}")

    # Behavior-based detection
    if behavior_model:
        packet_content = bytes(pkt).decode(errors='ignore')
        similarity_score = behavior_model.get_similarity(packet_content)
        
        print(f"[Detector] Behavior similarity score: {similarity_score:.2f}")
        if similarity_score > SIMILARITY_THRESHOLD:
            reason = f"可疑行為偵測 (相似度: {similarity_score:.2f})"
            raise_alert(pkt, reason)
            return
    else:
        print("[Detector] Behavior model not initialized, skipping behavior detection.")

    # Anomaly-based detection
    if model:
        features = extract_features(pkt)
        print(f"[Detector] Extracted features: {features}")
        try:
            prediction = model.predict([features])
            if prediction[0] == -1:
                raise_alert(pkt, "異常流量偵測")
                print("[Detector] Anomaly detected.")
            else:
                print("[Detector] Packet is normal (anomaly detection).")
        except Exception as e:
            print(f"[Detector ERROR] Error during anomaly detection prediction: {e}")
    else:
        print("[Detector] Anomaly detection model not initialized, skipping anomaly detection.")