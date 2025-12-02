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
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_test_data(test_size=None, test_percentage=None):
    """
    Load test data from CSV files
    If test_size is None and test_percentage is None, use all available data
    If test_percentage is specified (e.g., 0.2 for 20%), use that percentage
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
        
        total_samples = len(df)
        
        # Handle percentage-based sampling
        if test_percentage is not None:
            test_size = int(len(df) * test_percentage)
            df = df.sample(n=test_size, random_state=42)
            logger.info(f"Loaded {len(df)} test samples ({test_percentage*100:.1f}% of {total_samples} total)")
        # Sample if needed (only if test_size is specified and dataset is larger)
        elif test_size is not None and len(df) > test_size:
            df = df.sample(n=test_size, random_state=42)
            logger.info(f"Loaded {len(df)} test samples (sampled from {total_samples} total)")
        else:
            logger.info(f"Loaded {len(df)} test samples (using all available data)")
        
        return df
    except Exception as e:
        logger.error(f"Error loading test data: {e}")
        return None

def process_url_batch(batch_data):
    """
    Process a batch of URLs in parallel
    Each worker process will load the model independently
    """
    results = []
    # Import here so each process loads it independently
    from predict import predict_url_type
    
    for url, true_label in batch_data:
        try:
            result = predict_url_type(url)
            pred_label = 0 if result['label'] == 'benign' else 1
            confidence = result['confidence']
            proba = confidence if pred_label == 1 else (1 - confidence)
            results.append((true_label, pred_label, proba, None))
        except Exception as e:
            results.append((None, None, None, str(e)))
    
    return results

def evaluate_model(test_size=None, test_percentage=None, n_workers=10):
    """
    Evaluate the ML model and return comprehensive metrics
    If test_size is None and test_percentage is None, uses all available data
    If test_percentage is specified (e.g., 0.2 for 20%), uses that percentage
    Uses parallel processing with n_workers processes (default: 10)
    """
    df = load_test_data(test_size=test_size, test_percentage=test_percentage)
    if df is None or len(df) == 0:
        return {"error": "Could not load test data"}
    
    y_true = []
    y_pred = []
    y_pred_proba = []
    errors = 0
    
    logger.info(f"Starting model evaluation with {n_workers} parallel workers...")
    logger.info(f"Processing {len(df)} URLs...")
    
    # Prepare data for parallel processing
    url_data = [(row['url'], row['label_binary']) for _, row in df.iterrows()]
    
    # Split into batches for parallel processing
    batch_size = max(1, len(url_data) // n_workers)
    batches = [url_data[i:i + batch_size] for i in range(0, len(url_data), batch_size)]
    
    # Process in parallel
    all_results = []
    completed = 0
    
    with ProcessPoolExecutor(max_workers=n_workers) as executor:
        # Submit all batches
        future_to_batch = {executor.submit(process_url_batch, batch): i 
                          for i, batch in enumerate(batches)}
        
        # Collect results as they complete
        for future in as_completed(future_to_batch):
            batch_idx = future_to_batch[future]
            try:
                batch_results = future.result()
                all_results.extend(batch_results)
                completed += len(batch_results)
                if completed % 1000 == 0:
                    logger.info(f"Processed {completed}/{len(url_data)} URLs...")
            except Exception as e:
                logger.error(f"Batch {batch_idx} failed: {e}")
                errors += len(batches[batch_idx])
    
    # Process results
    for true_label, pred_label, proba, error in all_results:
        if error is not None:
            errors += 1
            continue
        if true_label is not None:
            y_true.append(true_label)
            y_pred.append(pred_label)
            y_pred_proba.append(proba)
    
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
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Evaluate ML model on test data')
    parser.add_argument('--test_size', type=int, default=None, 
                       help='Number of test samples to use (e.g., 20000)')
    parser.add_argument('--test_percentage', type=float, default=None,
                       help='Percentage of dataset to use (e.g., 0.2 for 20%%)')
    parser.add_argument('--n_workers', type=int, default=10,
                       help='Number of parallel workers (default: 10)')
    
    # Support old positional arguments for backward compatibility
    if len(sys.argv) > 1 and not sys.argv[1].startswith('--'):
        args = argparse.Namespace()
        args.test_percentage = None
        args.test_size = None
        args.n_workers = 10
        
        try:
            # Try as percentage first
            val = float(sys.argv[1])
            if 0 < val <= 1:
                args.test_percentage = val
            else:
                args.test_size = int(val)
        except ValueError:
            print(f"Invalid argument: {sys.argv[1]}")
            sys.exit(1)
        
        if len(sys.argv) > 2:
            try:
                args.n_workers = int(sys.argv[2])
            except ValueError:
                print(f"Invalid n_workers: {sys.argv[2]}, using default 10")
    else:
        args = parser.parse_args()
    
    # Default: 20% of data with 10 workers if nothing specified
    if args.test_size is None and args.test_percentage is None:
        args.test_percentage = 0.2
    
    print("Evaluating ML Model...")
    print("=" * 50)
    if args.test_size:
        print(f"Using {args.test_size} test samples with {args.n_workers} parallel workers")
    else:
        print(f"Using {args.test_percentage*100:.1f}% of dataset with {args.n_workers} parallel workers")
    print("=" * 50)
    
    metrics = evaluate_model(test_size=args.test_size, test_percentage=args.test_percentage, n_workers=args.n_workers)
    
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

