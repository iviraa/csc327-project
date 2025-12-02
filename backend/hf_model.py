from transformers import pipeline

# Initialize the pipeline
model_name = "r3ddkahili/final-complete-malicious-url-model"
classifier = pipeline("text-classification", model=model_name)

def check_url(url):
    """Simple function to check if a URL is malicious or benign"""
    # Get all label scores to determine malicious vs benign
    result_all = classifier(url, top_k=4)  # Get all 4 labels
    
    # result_all is a list of dicts, each with 'label' and 'score'
    # Find the highest scoring label
    top_result = max(result_all, key=lambda x: x['score'])
    
    # Map LABEL_* to benign/malicious
    # Based on testing: LABEL_0 and LABEL_2 appear to be benign,
    # LABEL_1 and LABEL_3 appear to be malicious types (phishing, malware, etc.)
    label_name = top_result["label"]
    
    # Check individual malicious label scores
    label_1_score = next((r['score'] for r in result_all if r['label'] == 'LABEL_1'), 0.0)
    label_3_score = next((r['score'] for r in result_all if r['label'] == 'LABEL_3'), 0.0)
    malicious_score = label_1_score + label_3_score
    
    # If LABEL_1 or LABEL_3 have significant probability (>0.05), consider it malicious
    # This handles cases where LABEL_2 might be top but malicious indicators exist
    is_malicious = label_name in ['LABEL_1', 'LABEL_3'] or malicious_score > 0.05
    
    return {
        "label": "malicious" if is_malicious else "benign",
        "confidence": top_result["score"]
    }

# Example usage
if __name__ == "__main__":
    # Test with a single URL
    test_url = "https://example.com"
    result = check_url(test_url)
    print(f"URL: {test_url}")
    print(f"Classification: {result['label']}")
    print(f"Confidence: {result['confidence']:.2%}")