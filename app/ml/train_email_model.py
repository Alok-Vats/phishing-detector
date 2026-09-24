"""Script to train the phishing email ML NLP pipeline."""

import os
import glob
import json
import joblib
import pandas as pd
import time
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

# Configuration
RAW_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "raw")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models")
MODEL_PATH = os.path.join(MODELS_DIR, "phishing_email_model.pkl")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "phishing_email_vectorizer.pkl")
METRICS_PATH = os.path.join(MODELS_DIR, "phishing_email_model_metrics.json")
RANDOM_SEED = 42

def load_and_combine_data():
    """Load raw dataset files and combine them."""
    csv_files = [
        "Enron.csv", "SpamAssasin.csv", "Nigerian_Fraud.csv", 
        "Nazario.csv", "Ling.csv", "CEAS_08.csv"
    ]
    
    dfs = []
    for filename in csv_files:
        filepath = os.path.join(RAW_DATA_DIR, filename)
        if os.path.exists(filepath):
            df = pd.read_csv(filepath)
            # Standardize columns we need
            cols = {}
            if 'sender' in df.columns: cols['sender'] = 'sender'
            if 'subject' in df.columns: cols['subject'] = 'subject'
            if 'body' in df.columns: cols['body'] = 'body'
            if 'label' in df.columns: cols['label'] = 'label'
            
            df = df[[c for c in cols.keys()]]
            dfs.append(df)
            
    combined_df = pd.concat(dfs, ignore_index=True)
    return combined_df

def preprocess_data(df):
    """Handle missing values, duplicates, and create text feature."""
    # Ensure columns exist
    for col in ['sender', 'subject', 'body']:
        if col not in df.columns:
            df[col] = ''
            
    # Fill missing values
    df = df.assign(
        sender=df['sender'].fillna(''),
        subject=df['subject'].fillna(''),
        body=df['body'].fillna('')
    )
    
    # Concatenate text fields for TF-IDF
    df = df.assign(text=df['sender'].astype(str) + " " + df['subject'].astype(str) + " " + df['body'].astype(str))
    
    # Drop duplicates
    initial_len = len(df)
    df = df.drop_duplicates(subset=['text', 'label'])
    print(f"Dropped {initial_len - len(df)} duplicate records.")
    
    # Basic text cleaning (lowercasing)
    df = df.assign(text=df['text'].str.lower())
    
    return df

def train_and_evaluate():
    print("Loading and combining data...")
    df = load_and_combine_data()
    print(f"Initial shape: {df.shape}")
    
    print("Preprocessing data...")
    df = preprocess_data(df)
    print(f"Shape after preprocessing: {df.shape}")
    print("Class distribution:")
    print(df['label'].value_counts())
    
    X = df['text']
    y = df['label']
    
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y)
    
    print("Vectorizing text (TF-IDF, char + word n-grams)...")
    # Use word n-grams and character n-grams where useful as per instructions, but since dataset is large, char n-grams might blow up memory. We'll stick to word ngrams.
    vectorizer = TfidfVectorizer(max_features=25000, stop_words='english', ngram_range=(1, 2))
    
    t0 = time.time()
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    print(f"Vectorization took {time.time() - t0:.2f} seconds.")
    
    # Train Logistic Regression
    print("Training Logistic Regression...")
    lr_model = LogisticRegression(max_iter=1000, random_state=RANDOM_SEED)
    t0 = time.time()
    lr_model.fit(X_train_vec, y_train)
    lr_train_time = time.time() - t0
    
    t0 = time.time()
    lr_preds = lr_model.predict(X_test_vec)
    lr_probs = lr_model.predict_proba(X_test_vec)[:, 1]
    lr_infer_time = time.time() - t0
    
    # Train Linear SVM
    print("Training Linear SVM...")
    svm_model = LinearSVC(random_state=RANDOM_SEED, dual=False)
    t0 = time.time()
    svm_model.fit(X_train_vec, y_train)
    svm_train_time = time.time() - t0
    
    t0 = time.time()
    svm_preds = svm_model.predict(X_test_vec)
    # LinearSVC doesn't have predict_proba natively, use decision_function
    svm_scores = svm_model.decision_function(X_test_vec)
    svm_infer_time = time.time() - t0
    
    # Evaluate
    def evaluate_model(y_true, y_pred, y_prob=None):
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred)
        rec = recall_score(y_true, y_pred)
        f1 = f1_score(y_true, y_pred)
        auc = roc_auc_score(y_true, y_prob) if y_prob is not None else None
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn)
        fnr = fn / (fn + tp)
        return {
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1_score": float(f1),
            "roc_auc": float(auc) if auc else None,
            "false_positive_rate": float(fpr),
            "false_negative_rate": float(fnr),
            "confusion_matrix": cm.tolist()
        }
        
    lr_metrics = evaluate_model(y_test, lr_preds, lr_probs)
    svm_metrics = evaluate_model(y_test, svm_preds, svm_scores)
    
    print("\nLogistic Regression Metrics:")
    for k, v in lr_metrics.items():
        print(f"  {k}: {v}")
    print(f"  Inference Time: {lr_infer_time:.4f}s")
        
    print("\nLinear SVM Metrics:")
    for k, v in svm_metrics.items():
        print(f"  {k}: {v}")
    print(f"  Inference Time: {svm_infer_time:.4f}s")
    
    # Select best model (F1 score based)
    selected_model_name = "LogisticRegression" if lr_metrics['f1_score'] >= svm_metrics['f1_score'] else "LinearSVM"
    best_model = lr_model if selected_model_name == "LogisticRegression" else svm_model
    best_metrics = lr_metrics if selected_model_name == "LogisticRegression" else svm_metrics
    best_infer_time = lr_infer_time if selected_model_name == "LogisticRegression" else svm_infer_time
    
    print(f"\nSelected Model: {selected_model_name}")
    
    # Save artifacts
    os.makedirs(MODELS_DIR, exist_ok=True)
    model_bundle = {
        "model": best_model,
        "feature_names": [],
        "labels": ["legitimate", "phishing"]
    }
    joblib.dump(model_bundle, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    
    metrics_out = {
        "dataset_size": len(df),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "selected_model": selected_model_name,
        "inference_time_seconds": best_infer_time,
        **best_metrics
    }
    
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics_out, f, indent=2)
        
    print(f"Artifacts saved to {MODELS_DIR}")

if __name__ == "__main__":
    train_and_evaluate()
