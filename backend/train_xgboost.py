"""
CryptoC XGBoost Model Training
Trains an XGBoost classifier for phishing URL detection
Based on the methodology described in the research paper
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from scipy.sparse import hstack
import xgboost as xgb
import joblib
import os
import logging
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def extract_url_features(url):
    """
    Extract features from URL for ML model
    
    Features extracted:
    - URL length
    - Number of subdomains
    - Path segment count
    - Has IP address
    - Number of special characters
    - TLD type
    """
    parsed = urlparse(url)
    
    features = {
        'url_length': len(url),
        'subdomain_count': len(parsed.hostname.split('.')) - 2 if parsed.hostname else 0,
        'path_segment_count': len(parsed.path.strip('/').split('/')) if parsed.path else 0,
        'has_ip': int(bool(parsed.hostname and any(c.isdigit() for c in parsed.hostname.split('.')[0]))),
        'special_char_count': sum(1 for c in url if c in ['@', '?', '&', '=', '-', '_']),
        'has_https': int(parsed.scheme == 'https'),
        'query_length': len(parsed.query) if parsed.query else 0,
    }
    
    return features


def prepare_dataset(csv_path='data/urls.csv'):
    """
    Prepare dataset from CSV file
    
    Args:
        csv_path: Path to URLs CSV file
        
    Returns:
        X: Feature matrix
        y: Labels (0 = benign, 1 = malicious)
    """
    logger.info(f"Loading dataset from {csv_path}")
    df = pd.read_csv(csv_path)
    
    logger.info(f"Dataset size: {len(df)} samples")
    logger.info(f"Label distribution:\n{df['type'].value_counts()}")
    
    # Convert labels to binary
    # benign = 0, everything else (phishing, malware, defacement) = 1
    df['label'] = df['type'].apply(lambda x: 0 if x == 'benign' else 1)
    
    logger.info(f"\nBinary distribution:")
    logger.info(f"Benign: {(df['label'] == 0).sum()}")
    logger.info(f"Malicious: {(df['label'] == 1).sum()}")
    
    return df


def extract_features_from_df(df):
    """
    Extract features from dataframe of URLs
    
    Returns:
        X_text: TF-IDF features from raw URLs
        X_numeric: Numeric features
        vectorizer: Fitted TF-IDF vectorizer
        scaler: Fitted numeric scaler
    """
    logger.info("Extracting features...")
    
    # Extract numeric features
    logger.info("Extracting numeric features...")
    numeric_features = df['url'].apply(extract_url_features)
    X_numeric_df = pd.DataFrame(list(numeric_features))
    
    # TF-IDF on raw URLs (character-level)
    logger.info("Extracting TF-IDF features from URLs...")
    vectorizer = TfidfVectorizer(
        analyzer='char',
        ngram_range=(3, 5),  # Character trigrams to 5-grams
        max_features=5000,    # Limit features for efficiency
        min_df=2              # Ignore rare n-grams
    )
    X_text = vectorizer.fit_transform(df['url'])
    
    # Scale numeric features
    scaler = StandardScaler()
    X_numeric = scaler.fit_transform(X_numeric_df)
    
    logger.info(f"TF-IDF features: {X_text.shape[1]}")
    logger.info(f"Numeric features: {X_numeric.shape[1]}")
    
    return X_text, X_numeric, vectorizer, scaler


def train_xgboost_model(X_train, y_train, X_test, y_test):
    """
    Train XGBoost classifier
    
    Args:
        X_train: Training features
        y_train: Training labels
        X_test: Test features
        y_test: Test labels
        
    Returns:
        Trained XGBoost model
    """
    logger.info("Training XGBoost model...")
    
    # XGBoost parameters optimized for phishing detection
    params = {
        'objective': 'binary:logistic',
        'eval_metric': 'logloss',
        'max_depth': 6,
        'learning_rate': 0.1,
        'n_estimators': 200,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'random_state': 42,
        'tree_method': 'hist',  # Fast histogram-based algorithm
        'use_label_encoder': False
    }
    
    model = xgb.XGBClassifier(**params)
    
    # Train with evaluation set
    model.fit(
        X_train, 
        y_train,
        eval_set=[(X_test, y_test)],
        verbose=True
    )
    
    logger.info("Training completed!")
    
    return model


def evaluate_model(model, X_test, y_test):
    """
    Evaluate model performance
    
    Args:
        model: Trained model
        X_test: Test features
        y_test: Test labels
    """
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
    
    logger.info("\n" + "="*60)
    logger.info("MODEL EVALUATION")
    logger.info("="*60)
    
    # Predictions
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    # Accuracy
    accuracy = accuracy_score(y_test, y_pred)
    logger.info(f"\nAccuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    # ROC-AUC
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    logger.info(f"ROC-AUC: {roc_auc:.4f}")
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"\nConfusion Matrix:")
    logger.info(f"True Negatives:  {cm[0][0]}")
    logger.info(f"False Positives: {cm[0][1]}")
    logger.info(f"False Negatives: {cm[1][0]}")
    logger.info(f"True Positives:  {cm[1][1]}")
    
    # Classification Report
    logger.info("\nClassification Report:")
    report = classification_report(y_test, y_pred, target_names=['Benign', 'Malicious'])
    logger.info(report)
    
    # Calculate recall (critical for security)
    recall = cm[1][1] / (cm[1][1] + cm[1][0])
    precision = cm[1][1] / (cm[1][1] + cm[0][1])
    f1 = 2 * (precision * recall) / (precision + recall)
    
    logger.info(f"\nKey Metrics:")
    logger.info(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    logger.info(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    logger.info(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")


def save_model(model, vectorizer, scaler, output_dir='model'):
    """
    Save trained model and preprocessors
    
    Args:
        model: Trained XGBoost model
        vectorizer: Fitted TF-IDF vectorizer
        scaler: Fitted numeric scaler
        output_dir: Directory to save models
    """
    os.makedirs(output_dir, exist_ok=True)
    
    logger.info(f"\nSaving model to {output_dir}/")
    
    # Save XGBoost model
    joblib.dump(model, f'{output_dir}/xgboost_model.pkl')
    logger.info("✓ Saved xgboost_model.pkl")
    
    # Save vectorizer
    joblib.dump(vectorizer, f'{output_dir}/vectorizer.pkl')
    logger.info("✓ Saved vectorizer.pkl")
    
    # Save scaler
    joblib.dump(scaler, f'{output_dir}/scaler.pkl')
    logger.info("✓ Saved scaler.pkl")
    
    logger.info("\nModel saved successfully!")


def main():
    """
    Main training pipeline
    """
    logger.info("="*60)
    logger.info("CryptoC XGBoost Model Training")
    logger.info("="*60)
    
    # Load dataset
    df = prepare_dataset('data/urls.csv')
    
    # Extract features
    X_text, X_numeric, vectorizer, scaler = extract_features_from_df(df)
    
    # Combine features
    logger.info("\nCombining features...")
    X = hstack([X_text, X_numeric])
    y = df['label'].values
    
    logger.info(f"Final feature matrix: {X.shape}")
    
    # Split dataset (80/20 as mentioned in paper)
    logger.info("\nSplitting dataset (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, 
        test_size=0.2, 
        random_state=42,
        stratify=y  # Maintain class balance
    )
    
    logger.info(f"Training set: {X_train.shape[0]} samples")
    logger.info(f"Test set: {X_test.shape[0]} samples")
    
    # Train model
    model = train_xgboost_model(X_train, y_train, X_test, y_test)
    
    # Evaluate
    evaluate_model(model, X_test, y_test)
    
    # Save model
    save_model(model, vectorizer, scaler)
    
    logger.info("\n" + "="*60)
    logger.info("Training pipeline completed!")
    logger.info("="*60)


if __name__ == "__main__":
    main()

