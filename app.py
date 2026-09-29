import os
import sys
import time
import threading
from flask import Flask, render_template, jsonify, request

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
from database.database import (
    init_db, log_traffic, log_alert, get_traffic_logs, get_alerts, resolve_alert,
    get_dashboard_stats, get_protocol_distribution, get_attack_distribution,
    get_traffic_over_time, get_traffic_analysis
)
from simulator.traffic_generator import TrafficGenerator
from ml.predict import predict_traffic, get_model_payload
from ml.train_model import train_and_save_model

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY

# Background monitoring state
IS_MONITORING = False
MONITORING_THREAD = None
TRAFFIC_GENERATOR = TrafficGenerator()

def background_monitoring_worker():
    """Background worker that generates live traffic periodically when monitoring is ACTIVE."""
    global IS_MONITORING
    print("Background Live Monitoring Started.")
    while IS_MONITORING:
        try:
            # Generate 1 to 3 traffic flows per interval
            count = 2
            for _ in range(count):
                flow = TRAFFIC_GENERATOR.generate_single_flow()
                pred = predict_traffic(flow)

                # Log traffic
                log_traffic(flow, pred['prediction'], pred['confidence'])

                # Log alert if attack
                if pred['prediction'] != 'NORMAL':
                    log_alert(flow, pred['prediction'], pred['severity'], pred['confidence'], pred['description'])

            time.sleep(config.MONITORING_INTERVAL)
        except Exception as e:
            print(f"Error in background monitoring worker: {e}")
            time.sleep(2)
    print("Background Live Monitoring Stopped.")

@app.before_request
def setup_app():
    """Ensure database and model exist on application startup."""
    if not hasattr(app, '_initialized'):
        init_db()
        get_model_payload()
        app._initialized = True

@app.route('/')
def index():
    """Render main web dashboard."""
    return render_template('index.html')

# =========================================================================
# REST API ENDPOINTS
# =========================================================================

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get overall dashboard summary stats."""
    stats = get_dashboard_stats()
    attack_dist = get_attack_distribution()
    traffic_time = get_traffic_over_time()
    return jsonify({
        'status': 'success',
        'stats': stats,
        'attack_distribution': attack_dist,
        'traffic_over_time': traffic_time
    })

@app.route('/api/traffic', methods=['GET'])
def api_traffic():
    """Get traffic logs with optional filtering."""
    limit = request.args.get('limit', default=100, type=int)
    attack_type = request.args.get('attack_type', default=None, type=str)
    logs = get_traffic_logs(limit=limit, attack_type=attack_type)
    return jsonify({
        'status': 'success',
        'count': len(logs),
        'traffic': logs
    })

@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Get alerts with optional filtering."""
    status = request.args.get('status', default=None, type=str)
    severity = request.args.get('severity', default=None, type=str)
    attack_type = request.args.get('attack_type', default=None, type=str)
    limit = request.args.get('limit', default=100, type=int)

    alerts_list = get_alerts(status=status, severity=severity, attack_type=attack_type, limit=limit)
    return jsonify({
        'status': 'success',
        'count': len(alerts_list),
        'alerts': alerts_list
    })

@app.route('/api/generate-traffic', methods=['POST'])
def api_generate_traffic():
    """Generate synthetic network traffic records, run ML classification, and log to DB."""
    data = request.get_json(silent=True) or {}
    count = int(data.get('count', 5))
    attack_type = data.get('attack_type', None)
    if attack_type == 'RANDOM':
        attack_type = None

    results = []
    attacks_detected = 0

    for _ in range(count):
        flow = TRAFFIC_GENERATOR.generate_single_flow(attack_type=attack_type)
        pred = predict_traffic(flow)

        log_traffic(flow, pred['prediction'], pred['confidence'])

        if pred['prediction'] != 'NORMAL':
            log_alert(flow, pred['prediction'], pred['severity'], pred['confidence'], pred['description'])
            attacks_detected += 1

        flow['prediction'] = pred['prediction']
        flow['confidence'] = pred['confidence']
        flow['severity'] = pred['severity']
        results.append(flow)

    return jsonify({
        'status': 'success',
        'generated_count': len(results),
        'attacks_detected': attacks_detected,
        'records': results
    })

@app.route('/api/start-monitoring', methods=['POST'])
def api_start_monitoring():
    """Start live background traffic monitoring simulation."""
    global IS_MONITORING, MONITORING_THREAD
    if not IS_MONITORING:
        IS_MONITORING = True
        MONITORING_THREAD = threading.Thread(target=background_monitoring_worker, daemon=True)
        MONITORING_THREAD.start()
        return jsonify({'status': 'success', 'is_monitoring': True, 'message': 'Live monitoring simulation started.'})
    return jsonify({'status': 'success', 'is_monitoring': True, 'message': 'Live monitoring is already running.'})

@app.route('/api/stop-monitoring', methods=['POST'])
def api_stop_monitoring():
    """Stop live background traffic monitoring simulation."""
    global IS_MONITORING
    IS_MONITORING = False
    return jsonify({'status': 'success', 'is_monitoring': False, 'message': 'Live monitoring simulation stopped.'})

@app.route('/api/monitoring-status', methods=['GET'])
def api_monitoring_status():
    """Get live monitoring status."""
    global IS_MONITORING
    return jsonify({'status': 'success', 'is_monitoring': IS_MONITORING})

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def api_resolve_alert(alert_id):
    """Mark alert as RESOLVED."""
    success = resolve_alert(alert_id)
    if success:
        return jsonify({'status': 'success', 'message': f'Alert #{alert_id} marked as RESOLVED.'})
    return jsonify({'status': 'error', 'message': f'Alert #{alert_id} not found.'}), 404

@app.route('/api/model-performance', methods=['GET'])
def api_model_performance():
    """Get Random Forest model metrics, confusion matrix, and feature importances."""
    payload = get_model_payload()
    return jsonify({
        'status': 'success',
        'algorithm': 'Random Forest Classifier',
        'n_estimators': 100,
        'features': payload['features'],
        'classes': payload['classes'],
        'metrics': payload['metrics'],
        'confusion_matrix': payload['confusion_matrix'],
        'feature_importances': payload['feature_importances']
    })

@app.route('/api/protocol-distribution', methods=['GET'])
def api_protocol_distribution():
    """Get breakdown of traffic by protocol."""
    proto_dist = get_protocol_distribution()
    return jsonify({
        'status': 'success',
        'protocol_distribution': proto_dist
    })

@app.route('/api/traffic-analysis', methods=['GET'])
def api_traffic_analysis():
    """Get detailed traffic analytics for Analysis page."""
    analysis = get_traffic_analysis()
    proto_dist = get_protocol_distribution()
    attack_dist = get_attack_distribution()

    return jsonify({
        'status': 'success',
        'analysis': analysis,
        'protocol_distribution': proto_dist,
        'attack_distribution': attack_dist
    })

@app.route('/api/demo-step', methods=['POST'])
def api_demo_step():
    """Execute a step in Demo Mode to showcase automated detection pipeline."""
    data = request.get_json(silent=True) or {}
    step = data.get('step', 1)

    logs = []

    if step == 1:
        # Step 1: Generate a target attack flow (e.g. DOS or PORT_SCAN)
        attack_type = data.get('attack_type', 'DOS')
        flow = TRAFFIC_GENERATOR.generate_single_flow(attack_type=attack_type)
        logs.append(f"[{flow['timestamp']}] 📡 Traffic packet flow generated from {flow['source_ip']} to {flow['destination_ip']}:{flow['destination_port']} ({flow['protocol']})")
        logs.append(f"[{flow['timestamp']}] 📊 Flow metrics: {flow['packet_count']} packets, {flow['total_bytes']} bytes, {flow['packets_per_second']} pkts/sec")
        
        # Step 2: Feature extraction
        logs.append(f"[{flow['timestamp']}] ⚙️ Features extracted: [ports={flow['source_port']}->{flow['destination_port']}, packets={flow['packet_count']}, bytes={flow['total_bytes']}, rate={flow['connection_rate']} conn/s]")

        # Step 3: ML Prediction
        pred = predict_traffic(flow)
        logs.append(f"[{flow['timestamp']}] 🤖 Random Forest Classifier prediction: {pred['prediction']} (Confidence: {pred['confidence']}%)")

        # Step 4: Detection & Alert
        log_traffic(flow, pred['prediction'], pred['confidence'])
        alert_id = None
        if pred['prediction'] != 'NORMAL':
            alert_id = log_alert(flow, pred['prediction'], pred['severity'], pred['confidence'], pred['description'])
            logs.append(f"[{flow['timestamp']}] 🚨 {pred['severity']} severity alert generated (Alert ID: #{alert_id})")
            logs.append(f"[{flow['timestamp']}] 📝 Description: {pred['description']}")

        return jsonify({
            'status': 'success',
            'step': step,
            'flow': flow,
            'prediction': pred,
            'alert_id': alert_id,
            'logs': logs
        })

    return jsonify({'status': 'error', 'message': 'Invalid demo step'}), 400

if __name__ == '__main__':
    # Initialize DB and Model
    init_db()
    get_model_payload()
    print("=" * 60)
    print(" AI NETWORK TRAFFIC ANALYSIS & INTRUSION DETECTION SYSTEM ")
    print(" Running on: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
