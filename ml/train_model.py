import os
import sys
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from ml.feature_engineering import preprocess_features, get_feature_names
from simulator.traffic_generator import TrafficGenerator

def train_and_save_model(dataset_path=None, model_output_path=None):
    if dataset_path is None:
        dataset_path = config.TRAFFIC_CSV_PATH
    if model_output_path is None:
        model_output_path = config.MODEL_PATH

    # Check if dataset exists, if not generate it
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}. Generating synthetic dataset...")
        generator = TrafficGenerator()
        df_data = generator.generate_dataset(num_samples=1600, output_file=dataset_path)
    else:
        df_data = pd.read_csv(dataset_path)

    print(f"Loaded dataset with {len(df_data)} records.")

    # Feature Preprocessing
    X = preprocess_features(df_data)
    y = df_data['label']

    # Train / Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Initialize & Train Model
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # Model Evaluation
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average='weighted', zero_division=0
    )

    labels = sorted(list(set(y)))
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    # Feature Importance
    feature_names = get_feature_names()
    importances = clf.feature_importances_
    feature_importance_dict = {
        name: float(imp) for name, imp in zip(feature_names, importances)
    }

    # Prepare Payload
    model_payload = {
        'model': clf,
        'features': feature_names,
        'classes': labels,
        'metrics': {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'num_classes': len(labels),
            'classification_report': report_dict
        },
        'confusion_matrix': cm.tolist(),
        'feature_importances': feature_importance_dict
    }

    # Save to disk
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    joblib.dump(model_payload, model_output_path)

    print("\n==========================================")
    print("MODEL TRAINING COMPLETED SUCCESSFULLY")
    print("==========================================")
    print(f"Model saved to: {model_output_path}")
    print(f"Accuracy : {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall   : {recall * 100:.2f}%")
    print(f"F1 Score : {f1 * 100:.2f}%")
    print("==========================================\n")

    return model_payload

if __name__ == "__main__":
    train_and_save_model()
