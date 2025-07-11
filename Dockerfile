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