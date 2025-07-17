from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import requests
import os

app = FastAPI()

# Mount static files (CSS, JS, etc.)
app.mount("/static", StaticFiles(directory="./templates/static"), name="static")

templates = Jinja2Templates(directory="./templates")

# Configuration for the Aggregator URL
AGGREGATOR_BASE_URL = os.environ.get("AGGREGATOR_BASE_URL", "http://localhost:5000")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    alerts = []
    sensors = []
    try:
        # Fetch alerts from the aggregator (assuming an /api/alerts endpoint exists or will be created)
        # For now, we'll use a placeholder or fetch from the existing database directly if dashboard has DB access
        # For simplicity, let's assume alerts are fetched from the aggregator's /api/alerts endpoint
        alerts_response = requests.get(f"{AGGREGATOR_BASE_URL}/api/alerts")
        alerts_response.raise_for_status()
        alerts = alerts_response.json()
        # Assuming the alerts now contain CVE information from the aggregator
        # No direct change needed here, as the data is already in the 'alerts' list
    except requests.exceptions.RequestException as e:
        print(f"Error fetching alerts from aggregator: {e}")

    try:
        # Fetch sensor data from the aggregator
        sensors_response = requests.get(f"{AGGREGATOR_BASE_URL}/api/sensors")
        sensors_response.raise_for_status()
        sensors = sensors_response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching sensor data from aggregator: {e}")

    return templates.TemplateResponse("index.html", {"request": request, "alerts": alerts, "sensors": sensors})

# To run this file directly for testing:
# uvicorn dashboard:app --host 0.0.0.0 --port 8000 --reload