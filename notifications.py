import requests
import csv
import smtplib
import logging
from email.mime.text import MIMEText
from typing import Dict, Any

from config import LINE_TOKEN, SLACK_WEBHOOK, EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASSWORD, EMAIL_RECIPIENT, ELASTICSEARCH_HOST, ELASTICSEARCH_PORT, ELASTICSEARCH_INDEX
from elasticsearch import Elasticsearch, ConnectionError, TransportError

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    es = Elasticsearch([{'host': ELASTICSEARCH_HOST, 'port': ELASTICSEARCH_PORT, 'scheme': 'http'}])
    es.ping()
    logging.info("Successfully connected to Elasticsearch.")
except (ConnectionError, TransportError) as e:
    logging.error(f"Could not connect to Elasticsearch: {e}")
    es = None

def send_to_elasticsearch(alert: Dict[str, Any]) -> None:
    if not es:
        logging.warning("Elasticsearch client not initialized. Skipping sending alert.")
        return
    try:
        es.index(index=ELASTICSEARCH_INDEX, document=alert)
        logging.info(f"Alert sent to Elasticsearch: {alert.get('reason')}")
    except (ConnectionError, TransportError) as e:
        logging.error(f"Elasticsearch error while sending alert: {e}")
    except Exception as e:
        logging.error(f"Unexpected error sending to Elasticsearch: {e}", exc_info=True)

def send_email_notification(alert: Dict[str, Any]) -> None:
    if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASSWORD, EMAIL_RECIPIENT]):
        logging.warning("Email notification not configured. Skipping.")
        return

    subject = f"[入侵警示] {alert.get('reason', 'Unknown Alert')}"
    body = f"""
    時間: {alert.get("time", "N/A")}
    來源: {alert.get("src", "N/A")}
    目標: {alert.get("dst", "N/A")}
    原因: {alert.get("reason", "N/A")}
    Whois: {alert.get("whois", "N/A")}
    """
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = EMAIL_RECIPIENT

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        logging.info(f"Email notification sent for alert: {alert.get('reason')}")
    except smtplib.SMTPException as e:
        logging.error(f"Email notification error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error sending email notification: {e}", exc_info=True)

def send_line_notification(alert: Dict[str, Any]) -> None:
    if not LINE_TOKEN:
        logging.warning("LINE notification token not configured. Skipping.")
        return
    headers = {"Authorization": f"Bearer {LINE_TOKEN}"}
    message = f'【警示】\n時間: {alert.get("time", "N/A")}\n來源: {alert.get("src", "N/A")}\n目標: {alert.get("dst", "N/A")}\n原因: {alert.get("reason", "N/A")}'
    try:
        response = requests.post("https://notify-api.line.me/api/notify", headers=headers, data={"message": message})
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        logging.info(f"LINE notification sent for alert: {alert.get('reason')}")
    except requests.RequestException as e:
        logging.error(f"LINE notification error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error sending LINE notification: {e}", exc_info=True)

def send_slack_notification(alert: Dict[str, Any]) -> None:
    if not SLACK_WEBHOOK:
        logging.warning("Slack webhook not configured. Skipping.")
        return
    message = {
        "text": f'*[入侵警示]* {alert.get("time", "N/A")}\n來源: {alert.get("src", "N/A")} → 目標: {alert.get("dst", "N/A")}\n原因: {alert.get("reason", "N/A")}'
    }
    try:
        response = requests.post(SLACK_WEBHOOK, json=message)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        logging.info(f"Slack notification sent for alert: {alert.get('reason')}")
    except requests.RequestException as e:
        logging.error(f"Slack notification error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error sending Slack notification: {e}", exc_info=True)

def export_to_csv(alert: Dict[str, Any]) -> None:
    try:
        with open("alerts.csv", "a", newline='') as f:
            writer = csv.writer(f)
            writer.writerow([alert.get("time", "N/A"), alert.get("src", "N/A"), alert.get("dst", "N/A"), alert.get("reason", "N/A")])
        logging.info(f"Alert exported to CSV: {alert.get('reason')}")
    except IOError as e:
        logging.error(f"CSV export error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error exporting to CSV: {e}", exc_info=True)
