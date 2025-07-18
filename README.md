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
-   **Anomaly Detection:** Uses machine learning (Isolation Forest) to detect unusual traffic patterns.

---

## What's New in this Version

This version introduces significant improvements in project structure and maintainability:

-   **Modularized Dockerfiles:** Each core service (aggregator, dashboard, rule_updater, suricata) now has its own dedicated Dockerfile, leading to smaller, more efficient images and clearer separation of concerns.
-   **Refactored Docker Compose:** The `docker-compose.yml` has been updated to reflect the new modular structure, making it easier to manage and deploy individual services.
-   **Improved Testability:** Python import paths in test files have been corrected to align with the new directory structure, ensuring tests can be run reliably.

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
