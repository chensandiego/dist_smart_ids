import psycopg2
from config import DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT

def get_db_connection():
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP NOT NULL,
        src_ip VARCHAR(255) NOT NULL,
        dst_ip VARCHAR(255) NOT NULL,
        reason TEXT NOT NULL
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sensors (
        sensor_id VARCHAR(255) PRIMARY KEY,
        last_heartbeat TIMESTAMP NOT NULL,
        status VARCHAR(50) NOT NULL,
        cpu_usage REAL,
        memory_usage REAL,
        last_ip VARCHAR(255)
    );
    """)
    conn.commit()
    cur.close()
    conn.close()

def insert_alert(src, dst, reason):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO alerts (timestamp, src_ip, dst_ip, reason)
    VALUES (NOW(), %s, %s, %s);
    """, (src, dst, reason))
    conn.commit()
    cur.close()
    conn.close()

def get_alerts():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT timestamp, src_ip, dst_ip, reason FROM alerts ORDER BY timestamp DESC")
    alerts = cur.fetchall()
    cur.close()
    conn.close()
    return alerts

def update_sensor_heartbeat(sensor_id, status, cpu_usage, memory_usage, last_ip):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO sensors (sensor_id, last_heartbeat, status, cpu_usage, memory_usage, last_ip)
    VALUES (%s, NOW(), %s, %s, %s, %s)
    ON CONFLICT (sensor_id) DO UPDATE SET
        last_heartbeat = NOW(),
        status = %s,
        cpu_usage = %s,
        memory_usage = %s,
        last_ip = %s;
    """, (sensor_id, status, cpu_usage, memory_usage, last_ip, status, cpu_usage, memory_usage, last_ip))
    conn.commit()
    cur.close()
    conn.close()

def get_sensors():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT sensor_id, last_heartbeat, status, cpu_usage, memory_usage, last_ip FROM sensors ORDER BY last_heartbeat DESC")
    sensors = cur.fetchall()
    cur.close()
    conn.close()
    return sensors