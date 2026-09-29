import sqlite3
import os
import sys
from datetime import datetime, timedelta

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def get_db_connection():
    """Establish connection to SQLite database."""
    os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables and populate seed data if empty."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create traffic_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            source_port INTEGER NOT NULL,
            destination_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            packet_count INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            connection_duration REAL NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL
        )
    ''')

    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE'
        )
    ''')

    conn.commit()

    # Check if database is empty, populate initial sample logs & alerts if needed
    cursor.execute("SELECT COUNT(*) FROM traffic_logs")
    count = cursor.fetchone()[0]
    if count == 0:
        seed_initial_data(conn)

    conn.close()
    print(f"Database initialized at: {config.DATABASE_PATH}")

def seed_initial_data(conn):
    """Seed initial sample records into traffic_logs and alerts for demonstration."""
    from simulator.traffic_generator import TrafficGenerator
    from ml.predict import predict_traffic

    generator = TrafficGenerator()
    now = datetime.now()

    # Seed 50 traffic logs across different time slots
    for i in range(50):
        ts = (now - timedelta(minutes=50 - i)).strftime("%Y-%m-%d %H:%M:%S")
        record = generator.generate_single_flow(timestamp=ts)
        pred_res = predict_traffic(record)

        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO traffic_logs 
            (timestamp, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, total_bytes, connection_duration, prediction, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            record['timestamp'], record['source_ip'], record['destination_ip'],
            record['source_port'], record['destination_port'], record['protocol'],
            record['packet_count'], record['total_bytes'], record['connection_duration'],
            pred_res['prediction'], pred_res['confidence']
        ))

        # If attack, seed alert
        if pred_res['prediction'] != 'NORMAL':
            cursor.execute('''
                INSERT INTO alerts
                (timestamp, source_ip, attack_type, severity, confidence, description, status)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
            ''', (
                record['timestamp'], record['source_ip'], pred_res['prediction'],
                pred_res['severity'], pred_res['confidence'], pred_res['description']
            ))

    conn.commit()

def log_traffic(record, prediction, confidence):
    """Insert a single network flow prediction into traffic_logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO traffic_logs 
        (timestamp, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, total_bytes, connection_duration, prediction, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        record['timestamp'], record['source_ip'], record['destination_ip'],
        record['source_port'], record['destination_port'], record['protocol'],
        record['packet_count'], record['total_bytes'], record['connection_duration'],
        prediction, confidence
    ))
    conn.commit()
    conn.close()

def log_alert(record, attack_type, severity, confidence, description):
    """Insert an intrusion alert into alerts table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts
        (timestamp, source_ip, attack_type, severity, confidence, description, status)
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
    ''', (
        record['timestamp'], record['source_ip'], attack_type,
        severity, confidence, description
    ))
    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    return alert_id

def get_traffic_logs(limit=100, attack_type=None):
    """Fetch recent traffic logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if attack_type and attack_type.upper() != 'ALL':
        cursor.execute('''
            SELECT * FROM traffic_logs WHERE prediction = ? ORDER BY id DESC LIMIT ?
        ''', (attack_type.upper(), limit))
    else:
        cursor.execute('''
            SELECT * FROM traffic_logs ORDER BY id DESC LIMIT ?
        ''', (limit,))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_alerts(status=None, severity=None, attack_type=None, limit=100):
    """Fetch alerts with optional filtering."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if status and status.upper() != 'ALL':
        query += " AND status = ?"
        params.append(status.upper())
    
    if severity and severity.upper() != 'ALL':
        query += " AND severity = ?"
        params.append(severity.upper())

    if attack_type and attack_type.upper() != 'ALL':
        query += " AND attack_type = ?"
        params.append(attack_type.upper())

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def resolve_alert(alert_id):
    """Set alert status to RESOLVED."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET status = 'RESOLVED' WHERE id = ?", (alert_id,))
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated

def get_dashboard_stats():
    """Compute overall stats for dashboard cards."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM traffic_logs")
    total_traffic = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM traffic_logs WHERE prediction = 'NORMAL'")
    normal_traffic = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM traffic_logs WHERE prediction != 'NORMAL'")
    detected_attacks = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL' AND status = 'ACTIVE'")
    critical_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'ACTIVE'")
    active_alerts = cursor.fetchone()[0]

    conn.close()

    return {
        'total_traffic': total_traffic,
        'normal_traffic': normal_traffic,
        'detected_attacks': detected_attacks,
        'critical_alerts': critical_alerts,
        'active_alerts': active_alerts
    }

def get_protocol_distribution():
    """Get count of traffic flows grouped by protocol."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT protocol, COUNT(*) as count FROM traffic_logs GROUP BY protocol")
    rows = cursor.fetchall()
    conn.close()
    return {row['protocol']: row['count'] for row in rows}

def get_attack_distribution():
    """Get count of traffic flows grouped by prediction class."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT prediction, COUNT(*) as count FROM traffic_logs GROUP BY prediction")
    rows = cursor.fetchall()
    conn.close()
    return {row['prediction']: row['count'] for row in rows}

def get_traffic_over_time():
    """Get recent traffic counts grouped by time."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT strftime('%H:%M', timestamp) as time_slot, 
               COUNT(*) as total_flows,
               SUM(CASE WHEN prediction != 'NORMAL' THEN 1 ELSE 0 END) as attack_flows
        FROM traffic_logs 
        GROUP BY time_slot 
        ORDER BY id DESC LIMIT 15
    ''')
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return list(reversed(rows))

def get_traffic_analysis():
    """Detailed analytics for Traffic Analysis page."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Top source IPs
    cursor.execute("SELECT source_ip, COUNT(*) as count FROM traffic_logs GROUP BY source_ip ORDER BY count DESC LIMIT 5")
    top_sources = [dict(row) for row in cursor.fetchall()]

    # Top destination IPs
    cursor.execute("SELECT destination_ip, COUNT(*) as count FROM traffic_logs GROUP BY destination_ip ORDER BY count DESC LIMIT 5")
    top_destinations = [dict(row) for row in cursor.fetchall()]

    # Suspicious sources
    cursor.execute('''
        SELECT source_ip, prediction, COUNT(*) as count 
        FROM traffic_logs 
        WHERE prediction != 'NORMAL' 
        GROUP BY source_ip, prediction 
        ORDER BY count DESC LIMIT 5
    ''')
    suspicious_sources = [dict(row) for row in cursor.fetchall()]

    # Averages
    cursor.execute("SELECT AVG(packet_count) as avg_packets, AVG(total_bytes/max(1, connection_duration)) as avg_bytes_sec FROM traffic_logs")
    avg_row = cursor.fetchone()
    avg_packets = round(avg_row['avg_packets'] or 0, 1)
    avg_bytes_sec = round(avg_row['avg_bytes_sec'] or 0, 1)

    # Most frequent attack
    cursor.execute("SELECT prediction, COUNT(*) as count FROM traffic_logs WHERE prediction != 'NORMAL' GROUP BY prediction ORDER BY count DESC LIMIT 1")
    top_attack_row = cursor.fetchone()
    top_attack = top_attack_row['prediction'] if top_attack_row else "None"

    conn.close()

    return {
        'top_sources': top_sources,
        'top_destinations': top_destinations,
        'suspicious_sources': suspicious_sources,
        'avg_packets': avg_packets,
        'avg_bytes_sec': avg_bytes_sec,
        'top_attack': top_attack
    }
