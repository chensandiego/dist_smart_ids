import os
import time
import json
import requests
import threading
import psutil
from scapy.all import sniff
from detector import packet_handler
import config

# --- Global Variables ---
alert_cache = []

def send_heartbeat():
    """Periodically sends a heartbeat to the aggregator with sensor status."""
    while True:
        try:
            payload = {
                "sensor_id": config.SENSOR_ID,
                "status": "online",
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "timestamp": time.time()
            }
            # In a real system, you would have a dedicated heartbeat endpoint.
            # For now, we'll print it, but you'd send it to a URL.
            # requests.post(f"{config.AGGREGATOR_URL.rsplit('/', 1)[0]}/heartbeat", json=payload)
            print(f"❤️  Heartbeat: {payload}")
        except Exception as e:
            print(f"Error sending heartbeat: {e}")
        time.sleep(config.HEARTBEAT_INTERVAL_SECONDS)

def send_to_aggregator(alert):
    """Sends a single alert to the central aggregator."""
    try:
        response = requests.post(config.AGGREGATOR_URL, json=alert, timeout=10)
        response.raise_for_status() # Raises an exception for 4xx/5xx errors
        return True
    except requests.RequestException as e:
        print(f"Failed to send alert to aggregator: {e}")
        return False

def process_cached_alerts():
    """Tries to send any alerts that were cached due to network issues."""
    global alert_cache
    if not alert_cache:
        return

    print(f"Retrying to send {len(alert_cache)} cached alerts...")
    remaining_alerts = []
    for alert in alert_cache:
        if not send_to_aggregator(alert):
            remaining_alerts.append(alert)
    
    alert_cache = remaining_alerts
    save_cache()

def cache_alert(alert):
    """Saves an alert to the local cache file."""
    alert_cache.append(alert)
    save_cache()

def save_cache():
    """Writes the current alert cache to a file."""
    with open(config.LOCAL_CACHE_FILE, 'w') as f:
        json.dump(alert_cache, f)

def load_cache():
    """Loads cached alerts from a file on startup."""
    global alert_cache
    if os.path.exists(config.LOCAL_CACHE_FILE):
        with open(config.LOCAL_CACHE_FILE, 'r') as f:
            try:
                alert_cache = json.load(f)
                print(f"Loaded {len(alert_cache)} alerts from cache.")
            except json.JSONDecodeError:
                alert_cache = []

def handle_packet_and_send(packet):
    """
    Processes a single packet with the detector and sends the resulting alert.
    Caches the alert if sending fails.
    """
    alert = packet_handler(packet) # Assuming packet_handler returns a JSON-serializable dict
    if alert:
        print(f"🚨 Alert generated: {alert.get('alert_id', 'N/A')}")
        if not send_to_aggregator(alert):
            print("Caching alert for later.")
            cache_alert(alert)
        else:
            # If we successfully send an alert, try to clear any cached ones
            process_cached_alerts()

def main():
    print("--- Starting Distributed IDS Sensor ---")
    print(f"Sensor ID: {config.SENSOR_ID}")
    print(f"Aggregator URL: {config.AGGREGATOR_URL}")
    print(f"Network Interface: {config.NETWORK_INTERFACE}")
    print("-------------------------------------")

    # Load any previously cached alerts
    load_cache()

    # Start the heartbeat thread
    heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
    heartbeat_thread.start()

    # Start sniffing the network
    print(f"👃 Sniffing on interface: {config.NETWORK_INTERFACE}")
    try:
        sniff(iface=config.NETWORK_INTERFACE, prn=handle_packet_and_send, store=False)
    except Exception as e:
        print(f"Error starting sniffer: {e}")
        print("Please ensure you are running this script with sufficient privileges")
        print("and that the specified network interface is correct.")

if __name__ == "__main__":
    main()