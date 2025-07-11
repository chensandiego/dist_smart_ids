import requests
import csv
import smtplib
from email.mime.text import MIMEText
from config import LINE_TOKEN, SLACK_WEBHOOK, EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASSWORD, EMAIL_RECIPIENT, ELASTICSEARCH_HOST, ELASTICSEARCH_PORT, ELASTICSEARCH_INDEX
from elasticsearch import Elasticsearch

es = Elasticsearch([{'host': ELASTICSEARCH_HOST, 'port': ELASTICSEARCH_PORT, 'scheme': 'http'}])

def send_to_elasticsearch(alert):
    try:
        es.index(index=ELASTICSEARCH_INDEX, body=alert)
    except Exception as e:
        print(f"Elasticsearch error: {e}")

def send_email_notification(alert):
    if not all([EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASSWORD, EMAIL_RECIPIENT]):
        return

    subject = f"[入侵警示] {alert['reason']}"
    body = f"""
    時間: {alert["time"]}
    來源: {alert["src"]}
    目標: {alert["dst"]}
    原因: {alert["reason"]}
    Whois: {alert["whois"]}
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
    except smtplib.SMTPException as e:
        print(f"Email notification error: {e}")

def send_line_notification(alert):
    if not LINE_TOKEN: return
    headers = {"Authorization": f"Bearer {LINE_TOKEN}"}
    message = f'【警示】\n時間: {alert["time"]}\n來源: {alert["src"]}\n目標: {alert["dst"]}\n原因: {alert["reason"]}'
    try:
        requests.post("https://notify-api.line.me/api/notify", headers=headers, data={"message": message})
    except requests.RequestException as e:
        print(f"LINE notification error: {e}")

def send_slack_notification(alert):
    if not SLACK_WEBHOOK: return
    message = {
        "text": f'*[入侵警示]* {alert["time"]}\n來源: {alert["src"]} → 目標: {alert["dst"]}\n原因: {alert["reason"]}'
    }
    try:
        requests.post(SLACK_WEBHOOK, json=message)
    except requests.RequestException as e:
        print(f"Slack notification error: {e}")

def export_to_csv(alert):
    try:
        with open("alerts.csv", "a", newline='') as f:
            writer = csv.writer(f)
            writer.writerow([alert["time"], alert["src"], alert["dst"], alert["reason"]])
    except IOError as e:
        print(f"CSV export error: {e}")
