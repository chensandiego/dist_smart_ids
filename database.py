
import psycopg2
from psycopg2 import Error
from typing import List, Tuple, Optional, Dict, Any
import logging
import json

from config import DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT
from alert_correlator import CorrelatedIncident # Import CorrelatedIncident for type hinting

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_db_connection():
    conn = None
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        return conn
    except Error as e:
        logging.error(f"Error connecting to PostgreSQL database: {e}")
        return None

def init_db() -> None:
    conn = None
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            
            # Create correlated_incidents table
            cur.execute("""
            CREATE TABLE IF NOT EXISTS correlated_incidents (
                incident_id VARCHAR(255) PRIMARY KEY,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP NOT NULL,
                involved_ips TEXT[],
                involved_sensors TEXT[],
                alert_count INTEGER NOT NULL,
                severity VARCHAR(50) NOT NULL,
                status VARCHAR(50) NOT NULL,
                summary TEXT
            );
            """)
            logging.info("Table 'correlated_incidents' ensured.")

            # Create alerts table and add incident_id column if it doesn't exist
            cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                src_ip VARCHAR(255) NOT NULL,
                dst_ip VARCHAR(255) NOT NULL,
                reason TEXT NOT NULL,
                cve VARCHAR(255),
                incident_id VARCHAR(255) -- New column
            );
            """)
            logging.info("Table 'alerts' ensured.")

            # Add incident_id column to alerts table if it doesn't exist
            cur.execute("""
            DO $
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='incident_id') THEN
                    ALTER TABLE alerts ADD COLUMN incident_id VARCHAR(255);
                END IF;
            END
            $;
            """)
            logging.info("Column 'incident_id' in 'alerts' table ensured.")

            # Add foreign key constraint (optional, but good for integrity)
            # This might fail if there are existing alerts without a matching incident_id
            # For simplicity, we'll skip adding a strict FK for now, or ensure data integrity manually.
            # cur.execute("""
            # ALTER TABLE alerts
            # ADD CONSTRAINT fk_incident
            # FOREIGN KEY (incident_id)
            # REFERENCES correlated_incidents(incident_id);
            # """)
            
            conn.commit()
            cur.close()
            logging.info("Database initialized successfully.")
    except Error as e:
        logging.error(f"Error initializing database: {e}")
    finally:
        if conn:
            conn.close()

def insert_alert(src_ip: str, dst_ip: str, reason: str, cve: Optional[str] = None, incident_id: Optional[str] = None) -> None:
    conn = None
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO alerts (timestamp, src_ip, dst_ip, reason, cve, incident_id)
            VALUES (NOW(), %s, %s, %s, %s, %s);
            """, (src_ip, dst_ip, reason, cve, incident_id))
            conn.commit()
            cur.close()
            logging.info(f"Alert inserted: {reason} from {src_ip} to {dst_ip} (Incident: {incident_id})")
    except Error as e:
        logging.error(f"Error inserting alert: {e}")
    finally:
        if conn:
            conn.close()

def insert_correlated_incident(incident: CorrelatedIncident) -> None:
    conn = None
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            # Convert sets to lists for PostgreSQL TEXT[] type
            involved_ips_list = list(incident.involved_ips)
            involved_sensors_list = list(incident.involved_sensors)

            cur.execute("""
            INSERT INTO correlated_incidents (incident_id, start_time, end_time, involved_ips, involved_sensors, alert_count, severity, status, summary)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (incident_id) DO UPDATE SET
                end_time = EXCLUDED.end_time,
                involved_ips = EXCLUDED.involved_ips,
                involved_sensors = EXCLUDED.involved_sensors,
                alert_count = EXCLUDED.alert_count,
                severity = EXCLUDED.severity,
                status = EXCLUDED.status,
                summary = EXCLUDED.summary;
            """, (
                incident.incident_id,
                incident.start_time,
                incident.end_time,
                involved_ips_list,
                involved_sensors_list,
                incident.alert_count,
                incident.severity,
                incident.status,
                incident.summary
            ))
            conn.commit()
            cur.close()
            logging.info(f"Correlated incident inserted/updated: {incident.incident_id} (Severity: {incident.severity})")
    except Error as e:
        logging.error(f"Error inserting/updating correlated incident {incident.incident_id}: {e}")
    finally:
        if conn:
            conn.close()

def get_alerts() -> List[Tuple]:
    conn = None
    alerts = []
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT timestamp, src_ip, dst_ip, reason, cve, incident_id FROM alerts ORDER BY timestamp DESC")
            alerts = cur.fetchall()
            cur.close()
    except Error as e:
        logging.error(f"Error retrieving alerts: {e}")
    finally:
        if conn:
            conn.close()
    return alerts

def get_correlated_incidents() -> List[Dict[str, Any]]:
    conn = None
    incidents = []
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT incident_id, start_time, end_time, involved_ips, involved_sensors, alert_count, severity, status, summary FROM correlated_incidents ORDER BY end_time DESC")
            rows = cur.fetchall()
            for row in rows:
                incident = {
                    "incident_id": row[0],
                    "start_time": row[1],
                    "end_time": row[2],
                    "involved_ips": row[3],
                    "involved_sensors": row[4],
                    "alert_count": row[5],
                    "severity": row[6],
                    "status": row[7],
                    "summary": row[8]
                }
                incidents.append(incident)
            cur.close()
    except Error as e:
        logging.error(f"Error retrieving correlated incidents: {e}")
    finally:
        if conn:
            conn.close()
    return incidents
