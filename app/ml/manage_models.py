"""Model management CLI for versioning and tracking ML pipelines."""

import argparse
import hashlib
import json
import os
import shutil
import time
from datetime import datetime, timezone
import pandas as pd

from app.ml.train_model import train_and_save_model
from app.ml.train_email_model import load_and_combine_data, preprocess_data, train_and_evaluate

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODELS_DIR = os.path.join(BASE_DIR, "models")
REGISTRY_PATH = os.path.join(MODELS_DIR, "registry.json")


def load_registry():
    if not os.path.exists(REGISTRY_PATH):
        return {"url": [], "email": [], "production": {"url": None, "email": None}}
    with open(REGISTRY_PATH, "r") as f:
        return json.load(f)


def save_registry(registry):
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)


def hash_dataframe(df):
    """Compute a SHA256 hash of a dataframe's string representation to track dataset version."""
    return hashlib.sha256(pd.util.hash_pandas_object(df, index=True).values).hexdigest()[:12]


def train_url_model():
    print("Starting URL model training workflow...")
    dataset_path = os.path.join(BASE_DIR, "data", "raw", "phishing_urls.csv")
    
    # Analyze Dataset
    df = pd.read_csv(dataset_path)
    dataset_hash = hash_dataframe(df)
    class_dist = df['label'].value_counts().to_dict()
    
    timestamp = int(time.time())
    version = f"v{timestamp}"
    
    model_filename = f"phishing_url_model_{version}.pkl"
    metrics_filename = f"phishing_url_metrics_{version}.json"
    
    model_out = os.path.join(MODELS_DIR, model_filename)
    metrics_out = os.path.join(MODELS_DIR, metrics_filename)
    
    # Train
    metrics = train_and_save_model(dataset_path, model_out, metrics_out)
    
    # Register
    registry = load_registry()
    record = {
        "version": version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_type": "RandomForestClassifier",
        "hyperparameters": {"n_estimators": 150, "max_depth": 10, "min_samples_split": 2},
        "dataset_hash": dataset_hash,
        "dataset_size": len(df),
        "class_distribution": class_dist,
        "feature_version": "1.1",
        "metrics": metrics,
        "artifact_path": model_filename,
    }
    registry["url"].append(record)
    save_registry(registry)
    print(f"URL Model {version} registered successfully.")


def train_email_model_cli():
    print("Starting Email model training workflow...")
    # Wrap existing email training
    # For simplicity, we execute the normal train and rename/register
    df = load_and_combine_data()
    df = preprocess_data(df)
    dataset_hash = hash_dataframe(df)
    class_dist = df['label'].value_counts().to_dict()
    
    timestamp = int(time.time())
    version = f"v{timestamp}"
    
    # We call the existing function which saves to fixed paths, then we rename them
    train_and_evaluate()
    
    fixed_model = os.path.join(MODELS_DIR, "phishing_email_model.pkl")
    fixed_vec = os.path.join(MODELS_DIR, "phishing_email_vectorizer.pkl")
    fixed_met = os.path.join(MODELS_DIR, "phishing_email_model_metrics.json")
    
    new_model = f"phishing_email_model_{version}.pkl"
    new_vec = f"phishing_email_vectorizer_{version}.pkl"
    
    shutil.copy(fixed_model, os.path.join(MODELS_DIR, new_model))
    shutil.copy(fixed_vec, os.path.join(MODELS_DIR, new_vec))
    
    with open(fixed_met, "r") as f:
        metrics = json.load(f)
        
    registry = load_registry()
    record = {
        "version": version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_type": metrics.get("selected_model", "Unknown"),
        "dataset_hash": dataset_hash,
        "dataset_size": len(df),
        "class_distribution": class_dist,
        "feature_version": "tfidf_word_ngrams",
        "metrics": metrics,
        "artifact_path": new_model,
        "vectorizer_path": new_vec,
    }
    registry["email"].append(record)
    save_registry(registry)
    print(f"Email Model {version} registered successfully.")


def compare_models(model_type):
    registry = load_registry()
    models = registry.get(model_type, [])
    if not models:
        print(f"No models found for type {model_type}")
        return
        
    print(f"--- {model_type.upper()} Model Comparison ---")
    for m in models:
        acc = m['metrics'].get('accuracy', 0)
        f1 = m['metrics'].get('f1_score', 0)
        print(f"Version: {m['version']} | Hash: {m['dataset_hash']} | Acc: {acc:.4f} | F1: {f1:.4f} | Size: {m['dataset_size']}")


def promote_model(model_type, version):
    registry = load_registry()
    models = registry.get(model_type, [])
    target = next((m for m in models if m["version"] == version), None)
    
    if not target:
        print(f"Version {version} not found.")
        return
        
    # Explicit criteria validation
    acc = target['metrics'].get('accuracy', 0)
    if acc < 0.85:
        print(f"ERROR: Model {version} fails explicit promotion criteria (Accuracy {acc:.4f} < 0.85). Promotion aborted.")
        return
        
    print(f"Promoting {model_type} model {version} to production...")
    registry["production"][model_type] = version
    save_registry(registry)
    
    # Link to production paths
    prod_model_path = os.path.join(MODELS_DIR, f"phishing_{model_type}_model_prod.pkl")
    shutil.copy(os.path.join(MODELS_DIR, target["artifact_path"]), prod_model_path)
    
    prod_vec_path = None
    if "vectorizer_path" in target:
        prod_vec_path = os.path.join(MODELS_DIR, f"phishing_{model_type}_vectorizer_prod.pkl")
        shutil.copy(os.path.join(MODELS_DIR, target["vectorizer_path"]), prod_vec_path)
        
    # Update trusted hashes
    trusted_file = os.path.join(MODELS_DIR, "trusted_hashes.json")
    trusted = {}
    if os.path.exists(trusted_file):
        with open(trusted_file, "r") as f:
            trusted = json.load(f)
            
    def compute_hash(filepath):
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
        
    trusted[os.path.basename(prod_model_path)] = compute_hash(prod_model_path)
    if prod_vec_path:
        trusted[os.path.basename(prod_vec_path)] = compute_hash(prod_vec_path)
        
    with open(trusted_file, "w") as f:
        json.dump(trusted, f, indent=2)
        
    print("Promotion successful. Trusted hashes updated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML Model Management CLI")
    parser.add_argument("action", choices=["train", "compare", "promote"])
    parser.add_argument("--type", choices=["url", "email"], required=True)
    parser.add_argument("--version", help="Version to promote", default=None)
    
    args = parser.parse_args()
    
    if args.action == "train":
        if args.type == "url":
            train_url_model()
        else:
            train_email_model_cli()
    elif args.action == "compare":
        compare_models(args.type)
    elif args.action == "promote":
        if not args.version:
            print("ERROR: --version is required for promotion.")
        else:
            promote_model(args.type, args.version)
