
# Distributed Smart Intrusion Detection System (IDS)

A distributed smart intrusion detection system that uses machine learning to detect and classify network intrusions.

## Features

- Real-time network traffic monitoring
- Anomaly detection using Isolation Forest
- Packet enrichment with geolocation and WHOIS information
- Alerting and notification system
- Web-based dashboard for visualizing alerts

## Architecture

The system is composed of the following components:

- **pcap_monitor:** Captures network traffic and saves it to a pcap file.
- **detector:** Reads the pcap file, extracts features, and uses a machine learning model to detect anomalies.
- **enrichment:** Enriches the alerts with geolocation and WHOIS information.
- **aggregator:** Aggregates the alerts from the different detectors and stores them in a database.
- **database:** A PostgreSQL database to store the alerts.
- **notifications:** Sends notifications to the user when an alert is generated.
- **dashboard:** A web-based dashboard to visualize the alerts.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-username/distribute_smart_ids.git
   ```
2. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Set up the database:
   ```
   psql -U postgres -f database.sql
   ```

## Usage

1. Start the pcap monitor:
   ```
   python pcap_monitor.py
   ```
2. Start the detector:
   ```
   python detector.py
   ```
3. Start the enrichment service:
   ```
   python enrichment.py
   ```
4. Start the aggregator:
   ```
   python aggregator.py
   ```
5. Start the notification service:
   ```
   python notifications.py
   ```
6. Start the dashboard:
   ```
   python dashboard.py
   ```

## Testing

To run the tests, use the following command:
```
pytest
```
