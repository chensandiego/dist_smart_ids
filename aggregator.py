import pika
import json
from database import insert_alert, init_db
from notifications import send_line_notification, send_slack_notification, send_email_notification, send_to_elasticsearch, export_to_csv
from config import RABBITMQ_HOST, RABBITMQ_QUEUE, BLOCKING_ENABLED
from blocker import block_ip

def process_alert(ch, method, properties, body):
    try:
        alert = json.loads(body)
        print(f"[AGGR] Received alert: {alert['reason']}")

        # Insert into database
        cve = alert.get('cve')
        insert_alert(alert['src'], alert['dst'], alert['reason'], cve)

        # Send notifications
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
        print(f"[AGGR] Successfully processed alert: {alert['reason']}")

    except json.JSONDecodeError as e:
        print(f"[AGGR] Error decoding message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False) # Discard malformed message
    except Exception as e:
        print(f"[AGGR] Error processing alert: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True) # Requeue on processing failure

def start_aggregator():
    print("[*] Starting aggregator service...")
    init_db() # Ensure database and tables are created

    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
        channel = connection.channel()
        channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
        channel.basic_qos(prefetch_count=1) # Process one message at a time
        channel.basic_consume(queue=RABBITMQ_QUEUE, on_message_callback=process_alert)

        print("[*] Waiting for messages. To exit press CTRL+C")
        channel.start_consuming()

    except pika.exceptions.AMQPError as e:
        print(f"RabbitMQ connection error: {e}")
    except KeyboardInterrupt:
        print("[*] Stopping aggregator service.")
        if 'connection' in locals() and connection.is_open:
            connection.close()

if __name__ == "__main__":
    start_aggregator()
