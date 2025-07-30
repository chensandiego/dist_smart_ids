import pika
import json
import logging
from typing import Dict, Any
import threading

from database import insert_alert, init_db, insert_correlated_incident
from notifications import send_line_notification, send_slack_notification, send_email_notification, send_to_elasticsearch, export_to_csv
from config import RABBITMQ_HOST, RABBITMQ_QUEUE, BLOCKING_ENABLED
from blocker import block_ip
from alert_correlator import AlertCorrelator, CorrelatedIncident # Import the new correlator
import aws_cloudtrail_monitor

import ueba_monitor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize the correlator globally or pass it around
correlator = AlertCorrelator(correlation_window_seconds=300) # 5 minutes correlation window

def process_alert(ch, method, properties, body) -> None:
    try:
        alert: Dict[str, Any] = json.loads(body)
        logging.info(f"[AGGR] Received alert: {alert.get('reason', 'No reason provided')}")

        # Profile and detect anomalies with the UEBA monitor
        ueba_monitor.profile_user_activity(alert)
        ueba_monitor.detect_anomalies(alert)

        # Process alert with the correlator
        correlated_incident: CorrelatedIncident = correlator.process_alert(alert)
        if correlated_incident:
            logging.info(f"Alert correlated to incident: {correlated_incident.incident_id} (Severity: {correlated_incident.severity})")
            # Insert or update the correlated incident in the database
            insert_correlated_incident(correlated_incident)

        # Insert individual alert into database (can be removed if only correlated incidents are stored)
        cve: str = alert.get('cve', 'N/A')
        incident_id: str = correlated_incident.incident_id if correlated_incident else "N/A"
        insert_alert(alert.get('src', 'N/A'), alert.get('dst', 'N/A'), alert.get('reason', 'N/A'), cve, incident_id)

        # Send notifications (consider sending notifications for correlated incidents instead of raw alerts)
        send_line_notification(alert)
        send_slack_notification(alert)
        send_email_notification(alert)

        # Send to Elasticsearch
        send_to_elasticsearch(alert)

        # Export to CSV
        export_to_csv(alert)

        # Automated IP Blocking
        if BLOCKING_ENABLED and 'src' in alert:
            block_ip(alert['src'])

        ch.basic_ack(delivery_tag=method.delivery_tag)
        logging.info(f"[AGGR] Successfully processed alert: {alert.get('reason', 'No reason provided')}")

    except json.JSONDecodeError as e:
        logging.error(f"[AGGR] Error decoding message: {e}. Message body: {body.decode()}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Discard malformed message
    except Exception as e:
        logging.error(f"[AGGR] Error processing alert: {e}", exc_info=True)
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True) # Requeue on processing failure

def start_aws_monitor():
    """Starts the AWS CloudTrail monitor in a separate thread."""
    aws_thread = threading.Thread(target=aws_cloudtrail_monitor.main, daemon=True)
    aws_thread.start()
    logging.info("[*] AWS CloudTrail monitor started.")

def start_aggregator() -> None:
    logging.info("[*] Starting aggregator service...")
    init_db() # Ensure database and tables are created
    start_aws_monitor()

    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
        channel.basic_qos(prefetch_count=1) # Process one message at a time
        channel.basic_consume(queue=RABBITMQ_QUEUE, on_message_callback=process_alert)

        logging.info("[*] Waiting for messages. To exit press CTRL+C")
        channel.start_consuming()

    except pika.exceptions.AMQPError as e:
        logging.error(f"RabbitMQ connection error: {e}")
    except KeyboardInterrupt:
        logging.info("[*] Stopping aggregator service.")
        if 'connection' in locals() and connection.is_open:
            connection.close()

if __name__ == "__main__":
    start_aggregator()
