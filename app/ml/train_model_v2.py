"""Training pipeline for the v2 phishing URL classifier."""

from __future__ import annotations

import json
from pathlib import Path
import time

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from app.ml.preprocess import build_feature_frame, load_dataset
from app.ml.model_loader import load_model


DEFAULT_RANDOM_STATE = 42


def evaluate_existing_model(dataset_path: Path):
    """Evaluate existing model to compare with v2."""
    try:
        base_dir = Path(__file__).resolve().parent.parent.parent
        old_bundle = load_model(str(base_dir / "models" / "phishing_url_model.pkl"))
        if not old_bundle: return None
        dataset = load_dataset(dataset_path)
        # Note: build_feature_frame will use the NEW feature_extractor.py so we have to use old feature names
        features, labels = build_feature_frame(dataset)
        old_features = features.reindex(columns=old_bundle["feature_names"], fill_value=0)
        
        _, x_test, _, y_test = train_test_split(
            old_features,
            labels,
            test_size=0.25,
            random_state=DEFAULT_RANDOM_STATE,
            stratify=labels,
        )
        
        preds = old_bundle["model"].predict(x_test)
        return {
            "accuracy": round(float(accuracy_score(y_test, preds)), 4),
            "f1_score": round(float(f1_score(y_test, preds, pos_label="phishing")), 4),
        }
    except Exception as e:
        print("Error evaluating old model:", e)
        return None

def train_and_save_model_v2(
    dataset_path: str | Path,
    model_output_path: str | Path,
    metrics_output_path: str | Path,
) -> dict:
    
    dataset_p = Path(dataset_path)
    old_metrics = evaluate_existing_model(dataset_p)
    print("Old Model Metrics:", old_metrics)
    
    dataset = load_dataset(dataset_path)
    features, labels = build_feature_frame(dataset)

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.25,
        random_state=DEFAULT_RANDOM_STATE,
        stratify=labels,
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=2,
        random_state=DEFAULT_RANDOM_STATE,
    )
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision_score(y_test, predictions, pos_label="phishing")), 4),
        "recall": round(float(recall_score(y_test, predictions, pos_label="phishing")), 4),
        "f1_score": round(float(f1_score(y_test, predictions, pos_label="phishing")), 4),
        "train_size": int(len(x_train)),
        "test_size": int(len(x_test)),
        "feature_count": int(features.shape[1]),
        "old_model_accuracy": old_metrics.get("accuracy") if old_metrics else None,
        "old_model_f1": old_metrics.get("f1_score") if old_metrics else None,
    }
    print("New Model Metrics:", metrics)

    model_bundle = {
        "model": model,
        "feature_names": list(features.columns),
        "labels": sorted(labels.unique().tolist()),
    }
    
    model_path = Path(model_output_path)
    metrics_path = Path(metrics_output_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model_bundle, model_path)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


if __name__ == "__main__":
    BASE_DIR = Path(__file__).resolve().parent.parent.parent
    train_and_save_model_v2(
        dataset_path=BASE_DIR / "data" / "raw" / "phishing_urls.csv",
        model_output_path=BASE_DIR / "models" / "phishing_url_model_v2.pkl",
        metrics_output_path=BASE_DIR / "models" / "phishing_url_model_v2_metrics.json",
    )
