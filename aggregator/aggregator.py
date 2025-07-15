from fastapi import FastAPI, Request, Body
from pydantic import BaseModel
import uvicorn
import threading
import json
import pika
import time

from database import init_db, insert_alert, update_sensor_heartbeat, get_sensors
from notifications import send_line_notification, send_slack_notification, send_email_notification, send_to_elasticsearch, export_to_csv
from config import RABBITMQ_HOST, RABBITMQ_QUEUE, BLOCKING_ENABLED
from blocker import block_ip

app = FastAPI()

# Pydantic model for incoming heartbeat data
class HeartbeatData(BaseModel):
    sensor_id: str
    status: str
    cpu_usage: float
    memory_usage: float
    timestamp: float
    last_ip: str = None # Optional, will be filled by the server if not provided

# Pydantic model for sensor status (for dashboard display)
class SensorStatus(BaseModel):
    sensor_id: str
    last_heartbeat: str
    status: str
    cpu_usage: float
    memory_usage: float
    last_ip: str

# --- RabbitMQ Consumer Logic ---
def rabbitmq_consumer():
    print("[*] Starting RabbitMQ consumer thread...")
    init_db() # Ensure database and tables are created

    while True:
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(RABBITMQ_HOST))
            channel = connection.channel()
            channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue=RABBITMQ_QUEUE, on_message_callback=process_alert)

            print("[*] Waiting for messages. To exit press CTRL+C")
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError as e:
            print(f"[AGGR] RabbitMQ connection error: {e}. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            print(f"[AGGR] An unexpected error occurred in consumer: {e}. Retrying in 5 seconds...")
            time.sleep(5)

def process_alert(ch, method, properties, body):
    try:
        alert = json.loads(body)
        print(f"[AGGR] Received alert: {alert.get('reason', 'No reason')}")

        # Insert into database
        insert_alert(alert.get('src'), alert.get('dst'), alert.get('reason'))

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
        print(f"[AGGR] Successfully processed alert: {alert.get('reason', 'No reason')}")

    except json.JSONDecodeError as e:
        print(f"[AGGR] Error decoding message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
    except Exception as e:
        print(f"[AGGR] Error processing alert: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

# --- FastAPI Endpoints ---
@app.on_event("startup")
async def startup_event():
    # Start RabbitMQ consumer in a separate thread
    threading.Thread(target=rabbitmq_consumer, daemon=True).start()
    print("FastAPI app started and RabbitMQ consumer initiated.")

@app.post("/api/heartbeat")
async def receive_heartbeat(heartbeat: HeartbeatData, request: Request):
    # Get the sensor's IP address from the request if not provided in payload
    last_ip = heartbeat.last_ip if heartbeat.last_ip else request.client.host
    update_sensor_heartbeat(
        heartbeat.sensor_id,
        heartbeat.status,
        heartbeat.cpu_usage,
        heartbeat.memory_usage,
        last_ip
    )
    return {"message": "Heartbeat received"}

@app.get("/api/sensors", response_model=list[SensorStatus])
async def get_all_sensors():
    sensors_data = get_sensors()
    # Convert database rows to Pydantic models
    return [
        SensorStatus(
            sensor_id=s[0],
            last_heartbeat=s[1].isoformat(), # Convert datetime to string
            status=s[2],
            cpu_usage=s[3],
            memory_usage=s[4],
            last_ip=s[5]
        ) for s in sensors_data
    ]

@app.post("/api/alerts")
async def receive_alert(alert: dict = Body(...)):
    # This endpoint is for direct HTTP alerts, if needed. 
    # For now, alerts primarily come via RabbitMQ.
    # You might want to add more validation here.
    print(f"[AGGR] Received direct HTTP alert: {alert.get('reason', 'No reason')}")
    insert_alert(alert.get('src'), alert.get('dst'), alert.get('reason'))
    return {"message": "Alert received"}

# To run this file directly for testing:
# uvicorn aggregator:app --host 0.0.0.0 --port 5000 --reload