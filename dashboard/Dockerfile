FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboard.py .
COPY templates/ ./templates/

EXPOSE 8000

CMD ["uvicorn", "dashboard:app", "--host", "0.0.0.0", "--port", "8000"]