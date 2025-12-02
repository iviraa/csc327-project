#!/usr/bin/env python3
"""Display ML model metrics in a readable format"""

from evaluate_model import get_quick_metrics
import json

print("\n" + "="*60)
print("ML MODEL METRICS SUMMARY")
print("="*60)

metrics = get_quick_metrics()

if "error" in metrics:
    print(f"Error: {metrics['error']}")
else:
    print(f"Accuracy:     {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"Precision:    {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
    print(f"Recall:       {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
    print(f"F1 Score:     {metrics['f1_score']:.4f}")
    
    roc_auc_str = f"{metrics['roc_auc']:.4f}" if metrics['roc_auc'] else "N/A"
    avg_prec_str = f"{metrics['average_precision']:.4f}" if metrics['average_precision'] else "N/A"
    print(f"ROC-AUC:      {roc_auc_str}")
    print(f"Avg Precision: {avg_prec_str}")
    
    print("\nConfusion Matrix:")
    cm = metrics['confusion_matrix']
    print(f"  True Negative:  {cm['true_negative']}")
    print(f"  False Positive: {cm['false_positive']}")
    print(f"  False Negative: {cm['false_negative']}")
    print(f"  True Positive:  {cm['true_positive']}")
    
    print(f"\nTest Samples: {metrics['test_samples']}")
    print(f"Errors: {metrics['errors']}")
    
    if 'model_info' in metrics:
        info = metrics['model_info']
        print(f"\nModel Info:")
        print(f"  Benign Samples: {info.get('benign_samples', 'N/A')}")
        print(f"  Malicious Samples: {info.get('malicious_samples', 'N/A')}")
    
    print("\n" + "="*60)
    print("\nFull JSON output:")
    print(json.dumps({k: v for k, v in metrics.items() if k not in ['roc_curve', 'precision_recall_curve']}, indent=2))

