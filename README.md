
# Distributed Smart Intrusion Detection System (IDS)

A distributed smart intrusion detection system that uses machine learning to detect and classify network intrusions.

## Features

- Real-time network traffic monitoring
- Anomaly detection using Isolation Forest
- Behavior-based detection using Suricata rule similarity
- Packet enrichment with geolocation and WHOIS information
- Alerting and notification system
- Web-based dashboard for visualizing alerts

## Architecture

The system is composed of the following components:

- **pcap_monitor:** Captures network traffic and saves it to a pcap file.
- **detector:** Reads the pcap file, extracts features, and uses a machine learning model to detect anomalies. It also uses a behavior model to detect suspicious traffic based on similarity to Suricata rules.
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
2. Install the dependencies (preferably in a virtual environment):
   ```
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Set up the database:
   ```
   psql -U postgres -f database.sql
   ```

## Usage

1. Start the services from within the `dist_smart_ids` directory:
   ```
   python3 pcap_monitor.py &
   python3 enrichment.py &
   python3 aggregator.py &
   python3 notifications.py &
   python3 dashboard.py &
   ```
2. The dashboard will be available at http://127.0.0.1:5000.

## Testing

To run the tests, use the following command:
```
pytest
```
