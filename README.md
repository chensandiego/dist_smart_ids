# Distributed Smart Intrusion Detection System (IDS)

A distributed smart intrusion detection system that uses a combination of rule-based (Suricata) and machine learning techniques to detect and classify network intrusions. The system is designed with a central aggregator and lightweight, containerized sensors that can be deployed across a network.

## Architecture

The system is composed of two main parts: the **Central Aggregator** (run via `docker-compose`) and one or more **Standalone Sensors** (run as individual Docker containers).

### Central Aggregator Components:

-   **aggregator:** Consumes alerts from sensors, stores them in a database, sends notifications, and triggers automated responses.
-   **database:** A PostgreSQL database to store alerts.
-   **dashboard:** A web-based dashboard to visualize alerts.
-   **suricata / rule_updater:** Can be run centrally or on the sensor. Manages and updates threat detection rules.
-   **enrichment / notifications / blocker:** Supporting services for the aggregator.

### Standalone Sensor:

-   **pcap_monitor:** A lightweight, containerized service that sniffs network traffic on a specific host.
-   **detector:** Analyzes traffic to generate alerts.
-   **Heartbeat & Caching:** The sensor sends periodic status updates (heartbeats) to the aggregator and caches alerts locally if the aggregator is unreachable, preventing data loss.

## Features

-   **Distributed Monitoring:** Deploy lightweight, containerized sensors across your network for broad visibility.
-   **Live Traffic Analysis:** Real-time network traffic monitoring and analysis.
-   **Centralized Management:** A central aggregator collects and manages alerts from all sensors.
-   **Resilient Sensors:** Sensors have heartbeat monitoring and local alert caching to handle network disruptions.
-   **Automated Rule Updates:** Automatically downloads and updates Suricata rulesets.
-   **Threat Intelligence Integration:** Enriches alerts with AbuseIPDB information.
-   **Automated Response:** Can automatically block malicious IP addresses.
-   **Anomaly Detection:** Uses machine learning (Isolation Forest, DBSCAN) to detect unusual traffic patterns.
-   **Ransomware Detection:** Monitors network traffic for behavioral patterns indicative of ransomware activity (e.g., high volume of file operations on network shares).
-   **Golden/Silver Ticket Detection:** Initial implementation for detecting Golden Ticket and Silver Ticket attacks using Suricata rules.
-   **Alert Correlation and Prioritization:** Implements logic to correlate related alerts from different detection mechanisms and sensors, reducing alert fatigue and prioritizing the most critical threats.
-   **Suspicious Email Detection:** Connects to Microsoft Exchange servers to scan for suspicious emails, including phishing attempts and malicious attachments.
-   **DNS Analysis:** Analyzes DNS queries to detect potential threats like DNS tunneling and requests to known malicious domains.

---

## What's New in this Version

This version introduces significant improvements in project structure and maintainability, and new features:

-   **DNS Analysis:** A new `dns_analyzer.py` module has been added to analyze DNS queries for suspicious activity. This includes checks for unusually long query names (a potential sign of DNS tunneling) and queries to known malicious domains.
-   **Suspicious Email Detection:** A new `email_scanner.py` module has been added to connect to Microsoft Exchange servers via Exchange Web Services (EWS). The scanner fetches unread emails and analyzes them for suspicious headers, content, and attachments. Alerts are sent to the central aggregator. To enable this feature, you must set the `EXCHANGE_USERNAME`, `EXCHANGE_PASSWORD`, and `EXCHANGE_SERVER` environment variables.
-   **Golden/Silver Ticket Detection:** Initial Suricata rules (`rules/ad_attacks.rules`) have been added for Golden Ticket (SID 2000001) and Silver Ticket (SID 2000002) detection. The `suricata.yaml` has been updated to include this new rule file. Additionally, `suricata_alert_parser.py` has been modified to specifically handle these new alert SIDs, including a placeholder function `handle_ad_attack_alert` for future advanced processing. **Note:** The current rules are basic placeholders and will require further refinement for accurate detection and to minimize false positives.
-   **Modularized Dockerfiles:** Each core service (aggregator, dashboard, rule_updater, suricata) now has its own dedicated Dockerfile, leading to smaller, more efficient images and clearer separation of concerns.
-   **Refactored Docker Compose:** The `docker-compose.yml` has been updated to reflect the new modular structure, making it easier to manage and deploy individual services.
-   **Improved Testability:** Python import paths in test files have been corrected to align with the new directory structure, ensuring tests can be run reliably. Additionally, new test files have been added for the DNS analyzer and email scanner to ensure their functionality.
-   **Enhanced Error Handling, Logging, and Type Hinting:** Core Python modules (`aggregator.py`, `database.py`, `notifications.py`, `blocker.py`, `enrichment.py`, `detector.py`, `ransomware_detector.py`, `dashboard.py`, `suricata_alert_parser.py`, `pcap_monitor.py`) have been refactored for improved robustness, debuggability, and code quality.
-   **Alert Correlation and Prioritization:** A new `alert_correlator.py` module has been introduced to group related alerts into higher-fidelity incidents, with database schema updates (`database.py`) and dashboard integration (`dashboard/dashboard.py`, `templates/index.html`) to display these correlated incidents.

---

## Running the Entire Application

To run the complete Distributed Smart IDS, follow these steps:

### 1. Prerequisites
-   [Docker Desktop](https://www.docker.com/products/docker-desktop)
-   Python 3.8+

### 2. Clone the Repository
```bash
git clone https://github.com/your-username/distribute_smart_ids.git
cd distribute_smart_ids
```

### 3. Download GeoLite2 City Database
Obtain the `GeoLite2-City.mmdb` database from MaxMind (free with registration) and place it in the `dist_smart_ids` directory.

### 4. Configure and Start the Central Aggregator Services

Set environment variables in your shell (e.g., `ABUSEIPDB_API_KEY`, `BLOCKING_ENABLED`) and then build and start the central services:

```bash
# Example configuration
export ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_API_KEY"
export BLOCKING_ENABLED=true

# For Email Scanning (optional)
export EXCHANGE_USERNAME="your_email@example.com"
export EXCHANGE_PASSWORD="your_password"
export EXCHANGE_SERVER="your_exchange_server"

docker-compose up -d --build
```

### 5. Access the Dashboard
The central dashboard will be available at `http://localhost:8000`.

### 6. Deploying a Standalone Sensor (Optional)

The sensor is a self-contained Docker container that you can deploy on any machine you want to monitor. This is separate from the `docker-compose` setup.

#### a. Build the Sensor Docker Image
Navigate to the `sensor` directory and run the build command:
```bash
cd sensor/
docker build -t ids-sensor:latest .
cd ..
```

#### b. Run the Sensor Container
Deploy the sensor using the `docker run` command. You must configure it with environment variables to tell it its unique ID and where to send alerts.

**Key Environment Variables:**
-   `SENSOR_ID`: A unique name for this sensor (e.g., `web-server-1`, `office-pi-01`).
-   `AGGREGATOR_URL`: The full URL to your central aggregator's alert endpoint (e.g., `http://<YOUR_AGGREGATOR_IP>:5000/api/alerts`).
-   `NETWORK_INTERFACE`: The network interface the sensor should monitor (e.g., `eth0`, `enp0s3`).

**Example `docker run` command:**
```bash
docker run -d --name my-sensor-1 \
  -e SENSOR_ID="factory-floor-sensor" \
  -e AGGREGATOR_URL="http://<YOUR_AGGREGATOR_IP>:5000/api/alerts" \
  -e NETWORK_INTERFACE="eth0" \
  --net=host \
  ids-sensor:latest
```
> **Note:** `--net=host` is used to give the container direct access to the host's network interfaces for sniffing traffic. This is the simplest method, but be aware of the security implications of giving a container this level of access.

You can run this command on multiple machines to deploy a fleet of sensors, all reporting back to your central aggregator.

## Testing

To run the tests for the main application, first ensure you have a Python virtual environment set up and dependencies installed:

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

Then, run pytest from the project root:

```bash
PYTHONPATH=. ./venv/bin/pytest
```

## Adversary Emulation

This project includes a simple adversary emulation program, `adversary_emulator.py`, designed to test the effectiveness of the IDS by simulating various attack techniques based on the MITRE ATT&CK framework.

### How it Works

The emulator reads a list of attack scenarios from the `emulation_scenarios.json` file and executes them in sequence. Each scenario is a Python function that crafts and sends network packets to a target using the `scapy` library.

### Running the Emulator

1.  **Install Dependencies:**

    Ensure you have the necessary dependencies installed, including `scapy`:

    ```bash
    ./venv/bin/pip install -r requirements.txt
    ```

2.  **Run the Emulator:**

    Execute the `adversary_emulator.py` script with the `emulation_scenarios.json` file as an argument:

    ```bash
    python adversary_emulator.py emulation_scenarios.json
    ```

    The emulator will log the actions it takes to the console. You can monitor the `dist_smart_ids` logs and dashboard to verify that the attacks are being detected.

### Customizing Scenarios

You can easily add or modify attack scenarios by editing the `emulation_scenarios.json` file. Each object in the JSON array represents a single scenario and is defined by a `technique_id` and other parameters.

**Example Scenario:**

```json
{
    "technique_id": "T1046",
    "technique_name": "Port Scan",
    "target": "127.0.0.1",
    "ports": [80, 443, 22, 8080, 3389]
}
```

To add a new attack technique, you will need to:

1.  Add a new function to `adversary_emulator.py` that implements the desired attack.
2.  Add a new scenario to `emulation_scenarios.json` that calls the new function.

## Enhanced Ransomware Detection

This system includes an advanced behavior-based ransomware detection engine that analyzes network file share activity for patterns indicative of a ransomware attack.

### How it Works

The `ransomware_detector.py` module uses **Scapy** to perform deep packet inspection of SMB (Server Message Block) traffic, moving beyond simple payload inspection to accurately parse and analyze SMB commands. This allows for more sophisticated and reliable detection based on the following features:

-   **High-Volume File Operations:** Detects a sudden surge in file creation, write, read, rename, or delete operations from a single source IP, which is a common indicator of automated encryption activity.
-   **Filename Entropy Analysis:** Calculates the Shannon entropy of filenames in `CREATE` requests. Ransomware often generates random, high-entropy filenames (e.g., `kHj8dKj9LpW3qXo7.txt`) after encrypting files. The system flags activity with an average filename entropy exceeding a predefined threshold.
-   **Suspicious File Extension Monitoring:** Tracks file extensions in `CREATE` and `RENAME` operations. An alert is triggered if a significant number of files with known ransomware extensions (e.g., `.locked`, `.crypto`, `.encrypted`) are detected.
-   **Imbalanced Read/Write Ratio:** Monitors the ratio of file read to write operations. A high number of writes without corresponding reads can indicate that files are being overwritten with encrypted data.

When this combination of suspicious activities is detected, an alert with `cve="RANSOMWARE-BEHAVIOR-ENHANCED"` is generated and sent to the aggregator for immediate attention.

### Testing the Enhanced Detection

To validate the effectiveness of the enhanced ransomware detection, you can use the provided unit tests or create custom Scapy scripts to simulate ransomware-like behavior.

1.  **Run the Unit Tests:**

    The `tests/test_ransomware_detector.py` file contains a suite of tests that simulate various ransomware scenarios, including high-entropy filenames, suspicious extensions, and imbalanced read/write ratios. These tests mock the alerting function to avoid generating network traffic.

    ```bash
    PYTHONPATH=. ./venv/bin/pytest tests/test_ransomware_detector.py
    ```

2.  **Simulate with a Custom Scapy Script:**

    You can create a Python script using Scapy to generate real network traffic that mimics a ransomware attack. This allows you to test the full detection pipeline, from the sensor to the dashboard.

    **Example Scapy script for simulation:**

    ```python
    from scapy.all import *
    import time

    src_ip = "192.168.1.10"  # IP of the simulated infected host
    dst_ip = "192.168.1.20"  # IP of the file server

    # Simulate creating a file with a high-entropy name
    high_entropy_filename = "z5H8dKj9LpW3qXo7.txt"
    pkt_entropy = IP(src=src_ip, dst=dst_ip) / TCP(dport=445) / SMB2_Header(Command=0x05) / SMB2_Create_Request(Name=high_entropy_filename)
    send(pkt_entropy)

    time.sleep(1)

    # Simulate creating a file with a suspicious extension
    suspicious_filename = "important_document.locked"
    pkt_extension = IP(src=src_ip, dst=dst_ip) / TCP(dport=445) / SMB2_Header(Command=0x05) / SMB2_Create_Request(Name=suspicious_filename)
    send(pkt_extension)

    print("Enhanced ransomware simulation traffic sent.")
    ```

3.  **Verify Detection:**

    -   Check the logs of the `aggregator` service for alerts related to "Ransomware-like behavior detected."
    -   Access the dashboard to see if new ransomware alerts with the `cve="RANSOMWARE-BEHAVIOR-ENHANCED"` are displayed.
