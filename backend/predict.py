import joblib
import pandas as pd
from urllib.parse import urlparse
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import HuggingFace model
try:
    from hf_model import check_url as hf_check_url
    HF_MODEL_AVAILABLE = True
    logger.info("HuggingFace model loaded successfully")
except Exception as e:
    HF_MODEL_AVAILABLE = False
    logger.warning(f"Could not load HuggingFace model: {str(e)}. Will use custom model.")

# Load the custom model components only if needed
def load_custom_model():
    global model, vectorizer, scaler
    model = joblib.load("model/model.pkl")
    vectorizer = joblib.load("model/vectorizer.pkl")
    scaler = joblib.load("model/scaler.pkl")
    logger.info("Custom model components loaded successfully")

# === Feature Engineering Helpers ===

def extract_features(url):
    parsed = urlparse(url)
    url_length = len(url)
    subdomain_count = len(parsed.hostname.split(".")) - 2 if parsed.hostname else 0
    path_segment_count = len(parsed.path.strip("/").split("/")) if parsed.path else 0
    return pd.DataFrame([{
        "url": url,
        "url_length": url_length,
        "subdomain_count": subdomain_count,
        "path_segment_count": path_segment_count
    }])

def predict_with_custom_model(url):
    """Use the custom model to predict URL type"""
    # Load custom model if not already loaded
    if not 'model' in globals():
        load_custom_model()

    features_df = extract_features(url)

    # Vectorize the URL text
    url_vec = vectorizer.transform(features_df["url"])

    # Scale the numeric features
    numeric_feats = scaler.transform(features_df[["url_length", "subdomain_count", "path_segment_count"]])

    # Combine both sets of features
    from scipy.sparse import hstack
    final_input = hstack([url_vec, numeric_feats])

    # Predict class and probabilities
    prediction = model.predict(final_input)[0]
    probs = model.predict_proba(final_input)[0]
    confidence = max(probs)

    return {
        "label": prediction,
        "confidence": float(confidence)
    }

def predict_url_type(url):
    """Main prediction function that tries HuggingFace model first, then falls back to custom model"""
    try:
        if HF_MODEL_AVAILABLE:
            logger.info("Using HuggingFace model for prediction")
            result = hf_check_url(url)
            # Convert HF model's output format to match our API
            return {
                "label": "malicious" if result["label"] == "malicious" else "benign",
                "confidence": float(result["confidence"]),
                "model_used": "huggingface"
            }
        else:
            logger.info("Using custom model for prediction")
            result = predict_with_custom_model(url)
            result["model_used"] = "custom"
            return result
    except Exception as e:
        logger.error(f"Error in prediction: {str(e)}")
        # If HF model fails, try custom model as fallback
        if HF_MODEL_AVAILABLE:
            logger.info("Falling back to custom model")
            try:
                result = predict_with_custom_model(url)
                result["model_used"] = "custom"
                return result
            except Exception as e2:
                logger.error(f"Both models failed. Custom model error: {str(e2)}")
                raise Exception("All prediction models failed")
        raise e

# === Run prediction on sample input ===
if __name__ == "__main__":
    sample_url = input("Enter a URL to classify: ")
    result = predict_url_type(sample_url)
    print("\nPrediction Results:")
    print(f"Label: {result['label']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Model Used: {result['model_used']}")
