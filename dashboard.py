from flask import Flask, render_template
from database import get_alerts
import threading
from config import WEB_HOST, WEB_PORT

app = Flask(__name__)

@app.route("/")
def index():
    alerts = get_alerts()
    return render_template("index.html", alerts=alerts)

def start_web():
    thread = threading.Thread(target=lambda: app.run(debug=False, host=WEB_HOST, port=WEB_PORT, use_reloader=False))
    thread.start()
