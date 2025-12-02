# ML Models in CryptoC

CryptoC uses a **dual-model approach** for URL classification, providing redundancy and fallback capabilities.

## Model Architecture

### 1. HuggingFace Model (Primary)
- **Model**: `r3ddkahili/final-complete-malicious-url-model`
- **Type**: Pre-trained transformer model from HuggingFace
- **Location**: Loaded dynamically via `transformers` pipeline
- **Status**: ✅ Active (primary model)

**How it works:**
- Uses the `transformers` library to load a pre-trained model
- Returns labels as `LABEL_0`, `LABEL_1`, `LABEL_2`, `LABEL_3`
- Our code maps these to `benign`/`malicious` based on score analysis
- If `LABEL_1` or `LABEL_3` have significant probability (>0.05), classified as malicious

**Performance:**
- Accuracy: ~90%
- Precision: 100% (no false positives)
- Recall: ~67%
- F1 Score: ~0.80
- ROC-AUC: ~0.97

### 2. Custom Model (Fallback)
- **Type**: Custom scikit-learn model (joblib format)
- **Location**: `backend/model/` directory
- **Files Required**:
  - `model/model.pkl` - Trained classifier
  - `model/vectorizer.pkl` - Text vectorizer (TF-IDF or similar)
  - `model/scaler.pkl` - Feature scaler
- **Status**: ⚠️ Fallback only (requires model files)

**How it works:**
- Uses feature engineering: URL length, subdomain count, path segment count
- Combines text vectorization with numeric features
- Trained on the dataset in `backend/data/urls.csv`

**When it's used:**
- If HuggingFace model fails to load
- If HuggingFace model throws an error during prediction
- As a backup when primary model is unavailable

## Model Selection Logic

The prediction flow in `predict.py`:

1. **Try HuggingFace model first**
   ```python
   if HF_MODEL_AVAILABLE:
       result = hf_check_url(url)
       return result with model_used="huggingface"
   ```

2. **Fallback to custom model**
   ```python
   else:
       result = predict_with_custom_model(url)
       return result with model_used="custom"
   ```

3. **Error handling**
   - If HuggingFace fails, automatically tries custom model
   - If both fail, raises exception

## Model Files

### HuggingFace Model
- **No local files needed** - downloaded automatically on first use
- Cached by `transformers` library in `~/.cache/huggingface/`

### Custom Model
- **Files needed** (if you want to use the custom model):
  ```
  backend/model/
  ├── model.pkl          # Trained classifier
  ├── vectorizer.pkl     # Text vectorizer
  └── scaler.pkl         # Feature scaler
  ```
- **Note**: These files are **not** in the repository (excluded via `.gitignore`)
- You would need to train these models separately if you want to use the custom model

## Current Status

✅ **HuggingFace Model**: Active and working  
⚠️ **Custom Model**: Code exists but model files are not present (will fallback if HF fails)

## Training Custom Model (Optional)

If you want to train the custom model:

1. Use the data in `backend/data/urls.csv`
2. Train a scikit-learn model (e.g., RandomForest, SVM)
3. Save the model, vectorizer, and scaler to `backend/model/`
4. The code will automatically use it as a fallback

## Metrics

Both models can be evaluated using:
- `python3 backend/evaluate_model.py` - Direct evaluation
- `python3 backend/show_metrics.py` - Formatted metrics display
- `GET /metrics` - API endpoint (when backend is running)
- `GET /metrics/summary` - Quick summary endpoint

