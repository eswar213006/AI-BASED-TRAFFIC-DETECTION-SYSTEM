import pandas as pd
import numpy as np

# Map protocols to numerical features
PROTOCOL_MAP = {
    'TCP': 1,
    'UDP': 2,
    'ICMP': 3
}

FEATURE_COLUMNS = [
    'source_port',
    'destination_port',
    'protocol_code',
    'packet_count',
    'total_bytes',
    'average_packet_size',
    'connection_duration',
    'packets_per_second',
    'bytes_per_second',
    'failed_connections',
    'connection_rate'
]

def preprocess_features(data):
    """
    Preprocess raw network flow records (dict, list of dicts, or pandas DataFrame)
    into a structured numerical feature DataFrame matching FEATURE_COLUMNS.
    """
    if isinstance(data, dict):
        df = pd.DataFrame([data])
    elif isinstance(data, list):
        df = pd.DataFrame(data)
    elif isinstance(data, pd.DataFrame):
        df = data.copy()
    else:
        raise ValueError("Input data must be a dict, list of dicts, or pandas DataFrame")

    # Map Protocol column
    if 'protocol' in df.columns:
        df['protocol_code'] = df['protocol'].map(lambda p: PROTOCOL_MAP.get(str(p).upper(), 0))
    elif 'protocol_code' not in df.columns:
        df['protocol_code'] = 1  # Default to TCP

    # Ensure all required features are present
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    # Fill NaN / Inf values
    df = df[FEATURE_COLUMNS].fillna(0.0)
    df = df.replace([np.inf, -np.inf], 0.0)

    return df

def get_feature_names():
    """Return the list of numerical feature names used for ML."""
    return FEATURE_COLUMNS
