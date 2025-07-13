# Base image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Install Suricata and its dependencies
RUN apt-get update && apt-get install -y \
    suricata \
    libcap-ng-dev \
    libnetfilter-queue-dev \
    libyaml-dev \
    libpcre2-dev \
    liblz4-dev \
    libhtp-dev \
    libjansson-dev \
    libmagic-dev \
    libnfnetlink-dev \
    libnss3-dev \
    libnspr4-dev \
    libevent-dev \
    liblua5.1-dev \
    libhiredis-dev \
    libmaxminddb-dev \
    libunwind-dev \
    libcap-ng0 \
    libnetfilter-queue1 \
    libyaml-0-2 \
    libpcre2-8-0 \
    liblz4-1 \
    libhtp-2 \
    libjansson4 \
    libmagic1 \
    libnfnetlink0 \
    libnss3 \
    libnspr4 \
    libevent-2.1-7 \
    liblua5.1-0 \
    libhiredis0.14 \
    libmaxminddb0 \
    libunwind8 \
    && rm -rf /var/lib/apt/lists/*

# Copy Suricata rules
COPY rules/suricata.rules /etc/suricata/rules/
COPY rules/suricata.yaml /etc/suricata/suricata.yaml

# Expose the web dashboard port
EXPOSE 5000

# Set default environment variables
ENV LINE_TOKEN=""
ENV SLACK_WEBHOOK=""
ENV DB_HOST="localhost"
ENV DB_PORT="5432"
ENV DB_USER="postgres"
ENV DB_PASSWORD="password"
ENV DB_NAME="smart_ids"
ENV RABBITMQ_HOST="localhost"
ENV ELASTICSEARCH_HOST="localhost"

# Default command to run the IDS sensor
CMD ["python", "ids.py", "--mode", "live", "--web"]