# AI-Based Network Traffic Analysis and Intrusion Detection System (NIDS)

An Academic Computer Networks & Cybersecurity Case Study Project for B.Tech CSE.

---

## 📌 Abstract
Modern computer networks face sophisticated cyber threats including Denial of Service (DoS) floods, stealth port scans, and automated brute-force login attempts. Traditional rule-based Intrusion Detection Systems (IDS) rely on static signature matching, rendering them ineffective against novel anomalies and high-velocity traffic patterns. This project presents a functional prototype of an **AI-Assisted Network Intrusion Detection System** built using Python, Scikit-learn, Flask, and Chart.js. The system extracts statistical network flow metrics, uses a Random Forest Classifier to classify traffic into `NORMAL`, `PORT_SCAN`, `DOS`, or `BRUTE_FORCE`, logs alerts into an SQLite database, and presents real-time Security Operations Center (SOC) analytics via an interactive web dashboard.

---

## 🎯 Objectives
- **Simulate Network Flow Telemetry:** Generate realistic synthetic network flow records (pack/sec, bytes/sec, connection duration, failed attempts).
- **ML-Powered Threat Classification:** Train a multi-class Random Forest model to classify traffic with high accuracy and confidence metrics.
- **Automated Intrusion Alerting:** Automatically map threat predictions to visual severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and maintain an alert database.
- **Interactive SOC Dashboard:** Provide real-time chart visualisations, live monitoring toggle, filterable threat tables, model performance matrices, and an automated demonstration mode.

---

## 🛠️ Technology Stack
- **Backend:** Python 3, Flask, Scikit-learn, Pandas, NumPy, Joblib
- **Frontend:** HTML5, CSS3 (Vanilla Dark SOC styling), JavaScript (ES6+), Chart.js
- **Database:** SQLite3
- **Machine Learning Algorithm:** Random Forest Classifier (100 Trees, Max Depth 12)

---

## 🏗️ System Architecture
```text
                  +-----------------------------------+
                  |   Synthetic Network Traffic Flow  |
                  +-----------------------------------+
                                    |
                                    v
                  +-----------------------------------+
                  |  Feature Preprocessing Pipeline   |
                  |   (11 Numerical Flow Features)    |
                  +-----------------------------------+
                                    |
                                    v
                  +-----------------------------------+
                  |  Random Forest ML Classifier      |
                  |  (Inference & Confidence Score)   |
                  +-----------------------------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
            v                                               v
+-----------------------+                       +-----------------------+
|     NORMAL FLOW       |                       |    ATTACK DETECTED    |
| (Log to Traffic DB)   |                       | (Port Scan, DoS, etc) |
+-----------------------+                       +-----------------------+
                                                            |
                                                            v
                                                +-----------------------+
                                                | Alert Gen & Severity  |
                                                |  (SQLite DB Alert)    |
                                                +-----------------------+
                                                            |
                                                            v
                                                +-----------------------+
                                                | Real-time SOC Web UI  |
                                                +-----------------------+
```

---

## 📁 Folder Structure
```text
ai-network-intrusion-detection/
│
├── app.py                      # Main Flask application & REST API server
├── config.py                   # Global system configuration and file paths
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
│
├── data/                       # CSV Datasets
│   ├── network_traffic.csv     # Synthetic training flow records
│   └── alerts.csv              # Exported alert logs
│
├── database/                   # Database module
│   └── database.py             # SQLite helper functions, schema, and queries
│
├── ml/                         # Machine Learning pipeline
│   ├── feature_engineering.py  # Feature extraction & encoding pipeline
│   ├── train_model.py          # Model training script
│   └── predict.py              # Prediction inference wrapper
│
├── models/                     # Model binaries
│   └── intrusion_model.pkl     # Saved Random Forest model & metrics payload
│
├── simulator/                  # Traffic Simulation engine
│   └── traffic_generator.py    # Synthetic network flow generator
│
├── templates/                  # HTML templates
│   └── index.html              # Main SOC Dashboard web page
│
├── static/                     # Web assets
│   ├── style.css               # SOC dark theme styles
│   └── script.js               # Dashboard JS, Chart.js logic, API integration
│
└── screenshots/                # Project demonstration screenshots
```

---

## 🚀 Installation & How to Run

### Step 1: Clone or navigate to the project folder
```bash
cd ai-network-intrusion-detection
```

### Step 2: Create a virtual environment (Optional but Recommended)
On Windows:
```cmd
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Train the ML model (Optional - App trains automatically if missing)
```bash
python ml/train_model.py
```

### Step 5: Launch the Flask Application
```bash
python app.py
```

### Step 6: Open Web Dashboard
Open your browser and navigate to:
[http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🧠 How the Machine Learning Model Works
1. **Dataset Generation:** Generates 1,600 balanced synthetic traffic flows.
2. **Feature Preprocessing (`ml/feature_engineering.py`):** Converts raw network attributes into 11 numerical features:
   - `source_port`, `destination_port`, `protocol_code`
   - `packet_count`, `total_bytes`, `average_packet_size`
   - `connection_duration`, `packets_per_second`, `bytes_per_second`
   - `failed_connections`, `connection_rate`
3. **Training (`ml/train_model.py`):** Uses an 80/20 train-test split to train a `RandomForestClassifier`. Evaluates performance via Accuracy, Weighted Precision, Recall, F1 Score, and Confusion Matrix.
4. **Inference (`ml/predict.py`):** Returns predicted label (`NORMAL`, `PORT_SCAN`, `DOS`, `BRUTE_FORCE`), probability confidence, and visual severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

---

## 🔌 API Endpoints Documentation

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the main web dashboard |
| `GET` | `/api/stats` | Returns overall traffic and alert metrics |
| `GET` | `/api/traffic` | Returns recent network traffic logs |
| `GET` | `/api/alerts` | Returns intrusion alerts (with status & severity filters) |
| `POST` | `/api/generate-traffic` | Generates $N$ synthetic flows and runs ML classification |
| `POST` | `/api/start-monitoring` | Starts background live monitoring loop |
| `POST` | `/api/stop-monitoring` | Stops background live monitoring loop |
| `POST` | `/api/alerts/<id>/resolve` | Marks alert status as `RESOLVED` |
| `GET` | `/api/model-performance` | Returns ML metrics, confusion matrix, & feature importances |
| `GET` | `/api/protocol-distribution` | Returns flow count breakdown by protocol |
| `GET` | `/api/traffic-analysis` | Returns top source/destination IPs & flow averages |
| `POST` | `/api/demo-step` | Executes step-by-step demonstration scenario |

---

## 📷 Screenshots Section
Save your academic demonstration screenshots in the `screenshots/` directory:
1. `dashboard_overview.png` - Main SOC Overview with Chart.js visualisations.
2. `traffic_analysis.png` - Deep Traffic Inspection & Flow Metrics.
3. `intrusion_alerts.png` - Intrusion Alert Table with severity badges.
4. `model_performance.png` - Model metrics and Confusion Matrix grid.
5. `demo_mode.png` - Automated Demo Mode terminal drawer output.

---

## 🔮 Future Enhancements
- Integration with real packet capture drivers (PyPcap / Scapy) for live NIC interface sniffing.
- Deep Learning extension using LSTM / Autoencoders for sequence anomaly detection.
- Automated IP blocking (iptables / Windows Firewall API rule trigger).

---

## ⚠️ Limitations
- Prototype uses synthetic traffic flows designed for academic demonstration.
- Does not inject actual exploit payloads or capture raw network hardware frames.
- ML model accuracy depends on training feature distributions.
