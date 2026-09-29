import os
import sys
import joblib
import numpy as np

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from ml.feature_engineering import preprocess_features
from ml.train_model import train_and_save_model

# Cache model in memory
_MODEL_PAYLOAD = None

def get_model_payload():
    """Load cached model payload or train if missing."""
    global _MODEL_PAYLOAD
    if _MODEL_PAYLOAD is None:
        if not os.path.exists(config.MODEL_PATH):
            print(f"Model file not found at {config.MODEL_PATH}. Training new model...")
            _MODEL_PAYLOAD = train_and_save_model()
        else:
            _MODEL_PAYLOAD = joblib.load(config.MODEL_PATH)
    return _MODEL_PAYLOAD

def get_severity(prediction):
    """
    Map prediction class to visual security severity level.
    """
    severity_map = {
        'NORMAL': 'LOW',
        'BRUTE_FORCE': 'MEDIUM',
        'PORT_SCAN': 'HIGH',
        'DOS': 'CRITICAL'
    }
    return severity_map.get(prediction.upper(), 'LOW')

def get_alert_description(prediction, record):
    """Generate detailed cybersecurity alert description."""
    src_ip = record.get('source_ip', 'Unknown')
    dst_ip = record.get('destination_ip', 'Unknown')
    dst_port = record.get('destination_port', 'Unknown')
    
    if prediction == 'DOS':
        return f"High-volume DoS flow detected targeting {dst_ip}:{dst_port} from {src_ip} ({record.get('packet_count', 0)} pkts, {record.get('packets_per_second', 0)} pkts/sec)."
    elif prediction == 'PORT_SCAN':
        return f"Reconnaissance port scanning pattern detected from {src_ip} targeting host {dst_ip}."
    elif prediction == 'BRUTE_FORCE':
        return f"Repeated authentication failures and connection attempts from {src_ip} targeting service on port {dst_port}."
    else:
        return f"Normal network communication pattern observed between {src_ip} and {dst_ip}."

def predict_traffic(record):
    """
    Predict intrusion category for a single traffic record or list of records.
    Returns prediction dictionary or list of dicts.
    """
    payload = get_model_payload()
    clf = payload['model']

    X = preprocess_features(record)
    predictions = clf.predict(X)
    probabilities = clf.predict_proba(X)
    classes = clf.classes_

    is_single = isinstance(record, dict)
    records_list = [record] if is_single else record
    results = []

    for idx, r in enumerate(records_list):
        pred_label = str(predictions[idx])
        probs = probabilities[idx]
        max_prob_idx = np.argmax(probs)
        confidence = float(probs[max_prob_idx]) * 100.0
        severity = get_severity(pred_label)
        description = get_alert_description(pred_label, r)

        results.append({
            'prediction': pred_label,
            'confidence': round(confidence, 1),
            'severity': severity,
            'description': description
        })

    return results[0] if is_single else results

if __name__ == "__main__":
    test_record = {
        "source_ip": "192.168.1.250",
        "destination_ip": "10.0.0.20",
        "source_port": 45123,
        "destination_port": 80,
        "protocol": "TCP",
        "packet_count": 12000,
        "total_bytes": 8500000,
        "average_packet_size": 708.33,
        "connection_duration": 0.8,
        "packets_per_second": 15000.0,
        "bytes_per_second": 10625000.0,
        "failed_connections": 1,
        "connection_rate": 250.0
    }
    res = predict_traffic(test_record)
    print("Prediction Result:", res)
