
import os

# Database settings (PostgreSQL)
DB_NAME = os.environ.get("DB_NAME", "smart_ids")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "password")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")

# Message Queue settings (RabbitMQ)
RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "localhost")
RABBITMQ_QUEUE = "alerts_queue"

# Rule settings
SURICATA_RULES = "rules/suricata.rules"

# Notification settings
LINE_TOKEN = os.environ.get("LINE_TOKEN")
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK")

# Web dashboard settings
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000

# Email settings
EMAIL_HOST = "smtp.example.com"  # Replace with your SMTP server
EMAIL_PORT = 587
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
EMAIL_RECIPIENT = "recipient@example.com" # Replace with the recipient's email address

# Elasticsearch settings
ELASTICSEARCH_HOST = "localhost"
ELASTICSEARCH_PORT = 9200
ELASTICSEARCH_INDEX = "smart_ids_alerts"
