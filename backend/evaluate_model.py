"""
ML Model Evaluation Script
Computes comprehensive metrics including F1, ROC-AUC, precision, recall, and more
"""

import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    precision_recall_curve,
    average_precision_score
)
import logging
from predict import predict_url_type
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_test_data(test_size=1000):
    """
    Load test data from CSV files
    If test_size is specified, randomly sample that many examples
    """
    try:
        # Try to load from urls.csv
        df = pd.read_csv("data/urls.csv")
        
        # Map labels to binary: benign=0, malicious=1
        # Combine phishing, malware, defacement as malicious
        df['label_binary'] = df['type'].apply(
            lambda x: 0 if x == 'benign' else 1
        )
        
        # Sample if needed
        if test_size and len(df) > test_size:
            df = df.sample(n=test_size, random_state=42)
        
        logger.info(f"Loaded {len(df)} test samples")
        return df
    except Exception as e:
        logger.error(f"Error loading test data: {e}")
        return None

def evaluate_model(test_size=1000):
    """
    Evaluate the ML model and return comprehensive metrics
    """
    df = load_test_data(test_size)
    if df is None or len(df) == 0:
        return {"error": "Could not load test data"}
    
    y_true = []
    y_pred = []
    y_pred_proba = []
    errors = 0
    
    logger.info("Starting model evaluation...")
    
    for idx, row in df.iterrows():
        try:
            url = row['url']
            true_label = row['label_binary']
            
            # Get prediction
            result = predict_url_type(url)
            
            # Convert prediction to binary
            pred_label = 0 if result['label'] == 'benign' else 1
            confidence = result['confidence']
            
            # For probability of malicious class (class 1):
            # If predicted as malicious, use confidence as probability of malicious
            # If predicted as benign, use (1 - confidence) as probability of malicious
            proba = confidence if pred_label == 1 else (1 - confidence)
            
            y_true.append(true_label)
            y_pred.append(pred_label)
            y_pred_proba.append(proba)
            
        except Exception as e:
            errors += 1
            logger.warning(f"Error processing URL {idx}: {e}")
            continue
    
    if len(y_true) == 0:
        return {"error": "No successful predictions"}
    
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    y_pred_proba = np.array(y_pred_proba)
    
    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    # ROC-AUC
    try:
        roc_auc = roc_auc_score(y_true, y_pred_proba)
    except Exception as e:
        logger.warning(f"Could not calculate ROC-AUC: {e}")
        roc_auc = None
    
    # Average Precision (AP)
    try:
        avg_precision = average_precision_score(y_true, y_pred_proba)
    except Exception as e:
        logger.warning(f"Could not calculate Average Precision: {e}")
        avg_precision = None
    
    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    
    # Classification Report
    class_report = classification_report(
        y_true, y_pred, 
        target_names=['Benign', 'Malicious'],
        output_dict=True,
        zero_division=0
    )
    
    # ROC Curve data
    try:
        fpr, tpr, roc_thresholds = roc_curve(y_true, y_pred_proba)
        roc_curve_data = {
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
            "thresholds": roc_thresholds.tolist()
        }
    except Exception as e:
        logger.warning(f"Could not calculate ROC curve: {e}")
        roc_curve_data = None
    
    # Precision-Recall Curve data
    try:
        precision_curve, recall_curve, pr_thresholds = precision_recall_curve(y_true, y_pred_proba)
        pr_curve_data = {
            "precision": precision_curve.tolist(),
            "recall": recall_curve.tolist(),
            "thresholds": pr_thresholds.tolist()
        }
    except Exception as e:
        logger.warning(f"Could not calculate PR curve: {e}")
        pr_curve_data = None
    
    metrics = {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc) if roc_auc is not None else None,
        "average_precision": float(avg_precision) if avg_precision is not None else None,
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp)
        },
        "classification_report": class_report,
        "roc_curve": roc_curve_data,
        "precision_recall_curve": pr_curve_data,
        "test_samples": len(y_true),
        "errors": errors,
        "model_info": {
            "test_size": test_size,
            "benign_samples": int(np.sum(y_true == 0)),
            "malicious_samples": int(np.sum(y_true == 1))
        }
    }
    
    roc_auc_str = f"{roc_auc:.4f}" if roc_auc is not None else "N/A"
    logger.info(f"Evaluation complete. Accuracy: {accuracy:.4f}, F1: {f1:.4f}, ROC-AUC: {roc_auc_str}")
    
    return metrics

def get_quick_metrics():
    """
    Get quick metrics summary (faster, smaller test set)
    """
    return evaluate_model(test_size=100)

if __name__ == "__main__":
    print("Evaluating ML Model...")
    print("=" * 50)
    
    metrics = evaluate_model(test_size=500)
    
    if "error" in metrics:
        print(f"Error: {metrics['error']}")
    else:
        print("\nModel Performance Metrics:")
        print(f"Accuracy:  {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall:    {metrics['recall']:.4f}")
        print(f"F1 Score:  {metrics['f1_score']:.4f}")
        print(f"ROC-AUC:   {metrics['roc_auc']:.4f if metrics['roc_auc'] else 'N/A'}")
        print(f"Avg Precision: {metrics['average_precision']:.4f if metrics['average_precision'] else 'N/A'}")
        
        print("\nConfusion Matrix:")
        cm = metrics['confusion_matrix']
        print(f"True Negative:  {cm['true_negative']}")
        print(f"False Positive: {cm['false_positive']}")
        print(f"False Negative: {cm['false_negative']}")
        print(f"True Positive:  {cm['true_positive']}")
        
        print("\nClassification Report:")
        print(f"Benign - Precision: {metrics['classification_report']['Benign']['precision']:.4f}, "
              f"Recall: {metrics['classification_report']['Benign']['recall']:.4f}, "
              f"F1: {metrics['classification_report']['Benign']['f1-score']:.4f}")
        print(f"Malicious - Precision: {metrics['classification_report']['Malicious']['precision']:.4f}, "
              f"Recall: {metrics['classification_report']['Malicious']['recall']:.4f}, "
              f"F1: {metrics['classification_report']['Malicious']['f1-score']:.4f}")

