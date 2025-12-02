import joblib
import pandas as pd
from urllib.parse import urlparse
import os
import logging
from scipy.sparse import hstack

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Model loading state
xgboost_model = None
hf_model_available = False

# Try to import HuggingFace model (fallback)
try:
    from hf_model import check_url as hf_check_url
    hf_model_available = True
    logger.info("HuggingFace model available as fallback")
except Exception as e:
    hf_model_available = False
    logger.warning(f"HuggingFace model not available: {str(e)}")

def load_xgboost_model():
    """Load XGBoost model (primary model)"""
    global xgboost_model
    
    try:
        model_path = "model/xgboost_model.pkl"
        vectorizer_path = "model/vectorizer.pkl"
        scaler_path = "model/scaler.pkl"
        
        if not os.path.exists(model_path):
            logger.warning(f"XGBoost model not found at {model_path}")
            return False
            
        xgboost_model = {
            'model': joblib.load(model_path),
            'vectorizer': joblib.load(vectorizer_path),
            'scaler': joblib.load(scaler_path)
        }
        logger.info("XGBoost model loaded successfully (PRIMARY MODEL)")
        return True
        
    except Exception as e:
        logger.error(f"Error loading XGBoost model: {e}")
        xgboost_model = None
        return False

# Try to load XGBoost on import
load_xgboost_model()

# === Feature Engineering Helpers ===

def extract_url_features(url):
    """Extract numeric features from URL"""
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
    
    return pd.DataFrame([features])

def predict_with_xgboost(url):
    """
    Use XGBoost model to predict URL type (PRIMARY MODEL)
    
    Args:
        url: URL string to analyze
        
    Returns:
        Dict with label, confidence, and model info
    """
    global xgboost_model
    
    if xgboost_model is None:
        if not load_xgboost_model():
            raise Exception("XGBoost model not available")
    
    # Extract features
    numeric_df = extract_url_features(url)
    
    # TF-IDF features
    url_vec = xgboost_model['vectorizer'].transform([url])
    
    # Scale numeric features
    numeric_feats = xgboost_model['scaler'].transform(numeric_df)
    
    # Combine features
    final_input = hstack([url_vec, numeric_feats])
    
    # Predict
    prediction = xgboost_model['model'].predict(final_input)[0]
    probs = xgboost_model['model'].predict_proba(final_input)[0]
    
    # prediction is 0 (benign) or 1 (malicious)
    label = "benign" if prediction == 0 else "malicious"
    confidence = float(probs[prediction])
    
    return {
        "label": label,
        "confidence": confidence,
        "risk_score": float(probs[1] * 100)  # Malicious probability as risk score
    }

def predict_url_type(url):
    """
    Main prediction function
    Priority: XGBoost (primary) -> HuggingFace (fallback)
    
    Args:
        url: URL string to analyze
        
    Returns:
        Dict with prediction results
    """
    # Try XGBoost first (primary model as per research)
    if xgboost_model is not None:
        try:
            logger.info("Using XGBoost model for prediction (PRIMARY)")
            result = predict_with_xgboost(url)
            result["model_used"] = "xgboost"
            return result
        except Exception as e:
            logger.error(f"XGBoost prediction failed: {e}")
    
    # Fallback to HuggingFace if available
    if hf_model_available:
        try:
            logger.info("Using HuggingFace model for prediction (FALLBACK)")
            result = hf_check_url(url)
            return {
                "label": "malicious" if result["label"] == "malicious" else "benign",
                "confidence": float(result["confidence"]),
                "risk_score": float(result.get("confidence", 0.5) * 100),
                "model_used": "huggingface"
            }
        except Exception as e:
            logger.error(f"HuggingFace prediction failed: {e}")
    
    # No models available
    raise Exception("No prediction models available. Train XGBoost model or install HuggingFace model.")

# === Run prediction on sample input ===
if __name__ == "__main__":
    sample_url = input("Enter a URL to classify: ")
    result = predict_url_type(sample_url)
    print("\nPrediction Results:")
    print(f"Label: {result['label']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Model Used: {result['model_used']}")
