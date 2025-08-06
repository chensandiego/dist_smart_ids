import os
import re
import json
import logging
from exchangelib import Credentials, Account, Configuration, DELEGATE
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
import urllib3

from kafka import KafkaProducer
from kafka.errors import KafkaError

from config import KAFKA_HOST, KAFKA_TOPIC_EMAIL_ALERTS, EXCHANGE_USERNAME, EXCHANGE_PASSWORD, EXCHANGE_SERVER

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        logging.info(f"[EMAIL ALERT] Published to {topic}")
    except KafkaError as e:
        logging.error(f"Kafka error while publishing email alert: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in send_alert_to_kafka: {e}", exc_info=True)

# --- Email Analysis ---
def analyze_email_headers(email):
    suspicious_indicators = []
    if email.reply_to and email.reply_to.email_address != email.sender.email_address:
        suspicious_indicators.append("Mismatch between 'From' and 'Reply-To' headers.")
    return suspicious_indicators

def analyze_email_body(email):
    suspicious_indicators = []
    phishing_phrases = [
        r"verify your account",
        r"update your payment details",
        r"urgent action required",
        r"your account has been suspended"
    ]
    for phrase in phishing_phrases:
        if email.body and re.search(phrase, email.body, re.IGNORECASE):
            suspicious_indicators.append(f"Detected suspicious phrase: '{phrase}'")
    if email.body:
        suspicious_links = re.findall(r"(https?://[^\s]+)", email.body)
        if suspicious_links:
            suspicious_indicators.append(f"Found links in email: {', '.join(suspicious_links)}")
    return suspicious_indicators

def analyze_attachments(email):
    suspicious_indicators = []
    dangerous_extensions = [".exe", ".zip", ".scr", ".bat", ".pif", ".com"]
    if email.attachments:
        for attachment in email.attachments:
            for ext in dangerous_extensions:
                if attachment.name.lower().endswith(ext):
                    suspicious_indicators.append(f"Dangerous attachment type detected: {attachment.name}")
    return suspicious_indicators

# --- Main Scanner ---
def scan_exchange_inbox(producer):
    try:
        BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
        creds = Credentials(username=EXCHANGE_USERNAME, password=EXCHANGE_PASSWORD)
        config = Configuration(server=EXCHANGE_SERVER, credentials=creds)
        account = Account(primary_smtp_address=EXCHANGE_USERNAME, config=config,
                          autodiscover=False, access_type=DELEGATE)
        logging.info(f"Successfully connected to {EXCHANGE_SERVER} for account {EXCHANGE_USERNAME}")
        
        for email in account.inbox.filter(is_read=False):
            logging.info(f"Scanning email: '{email.subject}' from {email.sender.email_address}")
            
            all_suspicious_indicators = []
            all_suspicious_indicators.extend(analyze_email_headers(email))
            all_suspicious_indicators.extend(analyze_email_body(email))
            all_suspicious_indicators.extend(analyze_attachments(email))
            
            if all_suspicious_indicators:
                alert = {
                    "reason": "Suspicious Email Detected",
                    "subject": email.subject,
                    "sender": email.sender.email_address,
                    "indicators": all_suspicious_indicators
                }
                send_alert_to_kafka(producer, KAFKA_TOPIC_EMAIL_ALERTS, alert)
            else:
                logging.info(f"Email '{email.subject}' appears to be clean.")
                
            email.is_read = True
            email.save()

    except Exception as e:
        logging.error(f"An error occurred: {e}")

def main():
    producer = create_kafka_producer()
    if not producer:
        logging.error("Could not create Kafka producer. Exiting.")
        return

    logging.info("Starting email scanner...")
    scan_exchange_inbox(producer)
    logging.info("Email scanner finished.")

if __name__ == "__main__":
    main()