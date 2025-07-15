
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

# Network Interface for live capture
NETWORK_INTERFACE = os.environ.get("NETWORK_INTERFACE", "eth0") # Default to 'eth0' or your primary interface

# Threat Intelligence settings
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")

# Automated Response settings
BLOCKING_ENABLED = os.environ.get("BLOCKING_ENABLED", "False").lower() == "true"
BLOCKING_DURATION_MINUTES = int(os.environ.get("BLOCKING_DURATION_MINUTES", "60")) # Default to 60 minutes

# GeoIP settings
GEOLITE2_CITY_DB = os.environ.get("GEOLITE2_CITY_DB", "GeoLite2-City.mmdb") # Path to MaxMind GeoLite2 City database

# Passive DNS settings
PASSIVE_DNS_API_KEY = os.environ.get("PASSIVE_DNS_API_KEY")

# Email settings
EMAIL_HOST = "smtp.example.com"  # Replace with your SMTP server
EMAIL_PORT = 587
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
EMAIL_RECIPIENT = "recipient@example.com" # Replace with the recipient's email address

# --- Sensor Settings ---
# These settings are for the distributed sensors (pcap_monitor.py)
AGGREGATOR_URL = os.environ.get("AGGREGATOR_URL", "http://127.0.0.1:5000/api/alerts")
SENSOR_ID = os.environ.get("SENSOR_ID", "default-sensor-01")
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get("HEARTBEAT_INTERVAL_SECONDS", 60))
LOCAL_CACHE_FILE = "alert_cache.json"

# Elasticsearch settings
ELASTICSEARCH_HOST = "localhost"
ELASTICSEARCH_PORT = 9200
ELASTICSEARCH_INDEX = "smart_ids_alerts"
