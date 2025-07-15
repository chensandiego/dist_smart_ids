# Dockerfile for the IDS Sensor

FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Install necessary system packages
# tshark is for packet capture, gcc is for compiling some python packages
RUN apt-get update && apt-get install -y tshark gcc

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip uninstall -y numpy scikit-learn && \
    pip install --no-cache-dir -r requirements.txt

# Copy the sensor code
COPY pcap_monitor.py .
COPY config.py .
COPY detector.py .
COPY enrichment.py .
COPY behavior_model.py .
COPY model/ ./model/
COPY rules/ ./rules/
COPY GeoLite2-City.mmdb .

# Set environment variables for configuration
ENV AGGREGATOR_URL="http://aggregator:5000/alerts"
ENV SENSOR_ID="default-sensor"
ENV HEARTBEAT_INTERVAL=60

# Command to run the sensor
CMD ["python", "-u", "pcap_monitor.py"]
