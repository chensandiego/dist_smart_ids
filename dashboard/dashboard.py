from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import requests
import os
import logging
from typing import List, Dict, Any

app = FastAPI()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Mount static files (CSS, JS, etc.)
app.mount("/static", StaticFiles(directory="./templates/static"), name="static")

templates = Jinja2Templates(directory="./templates")

# Configuration for the Aggregator URL
AGGREGATOR_BASE_URL: str = os.environ.get("AGGREGATOR_BASE_URL", "http://localhost:5000")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request) -> HTMLResponse:
    alerts: List[Dict[str, Any]] = []
    sensors: List[Dict[str, Any]] = []
    correlated_incidents: List[Dict[str, Any]] = []
    
    # Fetch alerts from the aggregator
    try:
        alerts_response = requests.get(f"{AGGREGATOR_BASE_URL}/api/alerts")
        alerts_response.raise_for_status()
        alerts = alerts_response.json()
        logging.info("Successfully fetched alerts from aggregator.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching alerts from aggregator: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching alerts: {e}", exc_info=True)

    # Fetch sensor data from the aggregator
    try:
        sensors_response = requests.get(f"{AGGREGATOR_BASE_URL}/api/sensors")
        sensors_response.raise_for_status()
        sensors = sensors_response.json()
        logging.info("Successfully fetched sensor data from aggregator.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching sensor data from aggregator: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching sensor data: {e}", exc_info=True)

    # Fetch correlated incidents from the aggregator
    try:
        incidents_response = requests.get(f"{AGGREGATOR_BASE_URL}/api/incidents")
        incidents_response.raise_for_status()
        correlated_incidents = incidents_response.json()
        logging.info("Successfully fetched correlated incidents from aggregator.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching correlated incidents from aggregator: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching correlated incidents: {e}", exc_info=True)

    return templates.TemplateResponse("index.html", {"request": request, "alerts": alerts, "sensors": sensors, "incidents": correlated_incidents})

# To run this file directly for testing:
# uvicorn dashboard:app --host 0.0.0.0 --port 8000 --reload