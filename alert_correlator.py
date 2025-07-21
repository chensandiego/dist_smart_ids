import time
import logging
from collections import defaultdict
from typing import Dict, Any, List, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CorrelatedIncident:
    def __init__(self, incident_id: str, initial_alert: Dict[str, Any]):
        self.incident_id: str = incident_id
        self.start_time: float = time.time()
        self.end_time: float = time.time()
        self.involved_ips: set[str] = {initial_alert.get('src', 'unknown'), initial_alert.get('dst', 'unknown')}
        self.involved_sensors: set[str] = {initial_alert.get('sensor_id', 'unknown')}
        self.alert_count: int = 1
        self.severity: str = "Low" # Initial severity
        self.status: str = "Open"
        self.summary: str = f"Initial alert: {initial_alert.get('reason', 'N/A')}"
        self.raw_alerts: List[Dict[str, Any]] = [initial_alert]

    def add_alert(self, alert: Dict[str, Any]) -> None:
        self.end_time = time.time()
        self.involved_ips.add(alert.get('src', 'unknown'))
        self.involved_ips.add(alert.get('dst', 'unknown'))
        self.involved_sensors.add(alert.get('sensor_id', 'unknown'))
        self.alert_count += 1
        self.raw_alerts.append(alert)
        # TODO: Update severity and summary based on new alert

    def calculate_severity(self) -> None:
        # Placeholder for more sophisticated severity calculation
        if self.alert_count > 5:
            self.severity = "Medium"
        if any("RANSOMWARE" in alert.get('cve', '') for alert in self.raw_alerts):
            self.severity = "Critical"
        # More rules can be added here

class AlertCorrelator:
    def __init__(self, correlation_window_seconds: int = 300):
        self.correlation_window_seconds: int = correlation_window_seconds
        self.active_incidents: Dict[str, CorrelatedIncident] = {}
        self.incident_counter: int = 0

    def _generate_incident_id(self) -> str:
        self.incident_counter += 1
        return f"INC-{self.incident_counter:05d}-{int(time.time())}"

    def process_alert(self, alert: Dict[str, Any]) -> Optional[CorrelatedIncident]:
        # This is a simplified correlation logic. More complex rules will be added.
        src_ip = alert.get('src')
        dst_ip = alert.get('dst')
        reason = alert.get('reason')

        # Try to find an existing incident to correlate with
        for incident_id, incident in list(self.active_incidents.items()):
            # Basic correlation: same source IP and within time window
            if src_ip in incident.involved_ips and \
               (time.time() - incident.end_time) <= self.correlation_window_seconds:
                incident.add_alert(alert)
                incident.calculate_severity()
                logging.info(f"Correlated alert to existing incident {incident_id}. New alert count: {incident.alert_count}")
                return incident
            # Clean up old incidents
            elif (time.time() - incident.end_time) > self.correlation_window_seconds * 2: # Double the window for cleanup
                logging.info(f"Closing old incident {incident_id} due to inactivity.")
                # TODO: Persist incident to database here
                del self.active_incidents[incident_id]

        # If no existing incident found, create a new one
        new_incident_id = self._generate_incident_id()
        new_incident = CorrelatedIncident(new_incident_id, alert)
        self.active_incidents[new_incident_id] = new_incident
        logging.info(f"Created new incident: {new_incident_id} for alert: {reason}")
        return new_incident

# Example Usage (for testing)
if __name__ == "__main__":
    correlator = AlertCorrelator(correlation_window_seconds=10)

    # Simulate alerts
    alert1 = {"time": time.time(), "src": "192.168.1.10", "dst": "10.0.0.1", "reason": "Port Scan", "sensor_id": "sensor-1"}
    alert2 = {"time": time.time(), "src": "192.168.1.10", "dst": "10.0.0.2", "reason": "Multiple Login Failures", "sensor_id": "sensor-1"}
    alert3 = {"time": time.time(), "src": "192.168.1.10", "dst": "10.0.0.3", "reason": "Unusual Traffic", "sensor_id": "sensor-1"}
    alert4 = {"time": time.time(), "src": "192.168.1.11", "dst": "10.0.0.1", "reason": "Port Scan", "sensor_id": "sensor-2"}
    alert5 = {"time": time.time(), "src": "192.168.1.10", "dst": "10.0.0.4", "reason": "RANSOMWARE-BEHAVIOR", "cve": "RANSOMWARE-BEHAVIOR", "sensor_id": "sensor-1"}

    inc1 = correlator.process_alert(alert1)
    time.sleep(1) # Simulate some time passing
    inc2 = correlator.process_alert(alert2)
    time.sleep(1) # Simulate some time passing
    inc3 = correlator.process_alert(alert3)
    time.sleep(1) # Simulate some time passing
    inc4 = correlator.process_alert(alert4)
    time.sleep(1) # Simulate some time passing
    inc5 = correlator.process_alert(alert5)

    print("\n--- Active Incidents ---")
    for inc_id, inc in correlator.active_incidents.items():
        print(f"Incident ID: {inc.incident_id}")
        print(f"  Start Time: {time.ctime(inc.start_time)}")
        print(f"  End Time: {time.ctime(inc.end_time)}")
        print(f"  Involved IPs: {inc.involved_ips}")
        print(f"  Alert Count: {inc.alert_count}")
        print(f"  Severity: {inc.severity}")
        print(f"  Summary: {inc.summary}")
        print(f"  Raw Alerts (first 2): {inc.raw_alerts[:2]}...")
        print("------------------------")

    # Simulate time passing to close incidents
    time.sleep(15) # Longer than correlation_window_seconds
    correlator.process_alert({"src": "dummy", "dst": "dummy", "reason": "dummy", "sensor_id": "dummy"}) # Trigger cleanup
    print("\n--- Active Incidents After Cleanup ---")
    for inc_id, inc in correlator.active_incidents.items():
        print(f"Incident ID: {inc.incident_id}")
        print(f"  Alert Count: {inc.alert_count}")
        print(f"  Severity: {inc.severity}")
        print("------------------------")