from scapy.all import IP, wrpcap
from sklearn.ensemble import IsolationForest
from joblib import load
import time
import json
import re
import pika
from config import RABBITMQ_HOST, RABBITMQ_QUEUE
from enrichment import get_whois_info

model = load("model/isolation_forest_model.joblib")

def load_suricata_signatures(rule_path="rules/suricata.rules"):
    signatures = []
    with open(rule_path, 'r') as f:
        for line in f:
            if line.startswith('alert'):
                try:
                    msg = re.findall(r'msg:"([^"]+)"', line)[0]
                    pattern = re.findall(r'content:"([^"]+)"', line)[0]
                    signatures.append({'msg': msg, 'pattern': pattern})
                except:
                    continue
    return signatures

suricata_signatures = load_suricata_signatures()

def extract_features(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        return [len(pkt), ip_layer.ttl, ip_layer.proto, ip_layer.len]
    return [0, 0, 0, 0]

def match_suricata_signature(pkt):
    raw = bytes(pkt).decode(errors="ignore")
    for sig in suricata_signatures:
        if sig['pattern'] in raw:
            return sig['msg']
    return None

def raise_alert(pkt, reason):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src = pkt[IP].src if IP in pkt else "unknown"
    dst = pkt[IP].dst if IP in pkt else "unknown"

    whois_info = get_whois_info(src)

    alert = {
        "time": timestamp,
        "src": src,
        "dst": dst,
        "reason": reason,
        "whois": whois_info,
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
        print(f"RabbitMQ error: {e}")

def packet_handler(pkt):
    if IP not in pkt:
        return
    msg = match_suricata_signature(pkt)
    if msg:
        raise_alert(pkt, f"簽章比對：{msg}")
        return

    features = extract_features(pkt)
    prediction = model.predict([features])
    if prediction[0] == -1:
        raise_alert(pkt, "異常流量偵測")
