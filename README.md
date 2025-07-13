# Distributed Smart Intrusion Detection System (IDS)

A distributed smart intrusion detection system that uses machine learning to detect and classify network intrusions.

## Features

- **Live Traffic Analysis:** Real-time network traffic monitoring and analysis using Suricata.
- **Automated Rule Updates:** Automatically downloads and updates Suricata rulesets.
- **Threat Intelligence Integration:** Enriches alerts with AbuseIPDB information for suspicious IPs.
- **Automated Response:** Automatically blocks malicious IP addresses using `iptables`.
- **Enhanced Contextual Enrichment:** Enriches alerts with geolocation, passive DNS (placeholder), and port/service identification.
- Anomaly detection using Isolation Forest
- Behavior-based detection using Suricata rule similarity
- Alerting and notification system
- Web-based dashboard for visualizing alerts

## Architecture

The system is composed of the following components:

- **suricata:** Captures live network traffic and generates EVE JSON logs for alerts.
- **suricata_alert_parser:** Tails Suricata EVE JSON logs, enriches alerts with additional context (AbuseIPDB, geolocation, passive DNS, service names), and sends them to RabbitMQ.
- **detector:** (Legacy - primarily for PCAP analysis and ML anomaly detection, now supplemented by Suricata) Reads network traffic, extracts features, and uses a machine learning model to detect anomalies. It also uses a behavior model to detect suspicious traffic based on similarity to Suricata rules.
- **enrichment:** Provides functions for enriching alerts with WHOIS, AbuseIPDB, geolocation, passive DNS, and service identification information.
- **aggregator:** Consumes alerts from RabbitMQ, stores them in a database, sends notifications, and triggers automated responses (like IP blocking).
- **blocker:** Handles IP blocking using `iptables`.
- **rule_updater:** Downloads and updates Suricata rulesets.
- **database:** A PostgreSQL database to store the alerts.
- **notifications:** Sends notifications to the user when an alert is generated.
- **dashboard:** A web-based dashboard to visualize the alerts.
- **pcap_monitor:** Monitors a directory for PCAP files and processes them (legacy, primarily for offline analysis).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/distribute_smart_ids.git
    cd distribute_smart_ids
    ```
2.  **Download GeoLite2 City Database:**
    Obtain the `GeoLite2-City.mmdb` database from MaxMind (free with registration) and place it in the `dist_smart_ids` directory.

3.  **Build Docker images:**
    ```bash
    docker-compose build
    ```

## Usage

1.  **Set Environment Variables (Optional but Recommended):**
    *   `NETWORK_INTERFACE`: Your network interface for live traffic capture (e.g., `en0` on macOS, `eth0` on Linux).
    *   `BLOCKING_ENABLED`: Set to `true` to enable automated IP blocking (requires `NET_ADMIN` capability for the `aggregator` service).
    *   `ABUSEIPDB_API_KEY`: Your API key for AbuseIPDB.
    *   `PASSIVE_DNS_API_KEY`: Your API key for a Passive DNS service (for future integration).

    Example:
    ```bash
    export NETWORK_INTERFACE=en0
    export BLOCKING_ENABLED=true
    export ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_API_KEY"
    docker-compose up -d
    ```

2.  **Start the services:**
    ```bash
    docker-compose up -d
    ```

3.  **Access the web dashboard:**
    The dashboard will be available at `http://localhost:5000`.

4.  **Update rules manually (or schedule):**
    To manually trigger a rule update:
    ```bash
    docker-compose run --rm rule_updater
    ```
    In a production environment, you would typically schedule this to run periodically.

## Testing

To run the tests, use the following command:
```bash
pytest
```