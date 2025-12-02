# CryptoC Backend

Flask-based backend API for Web3 security: ML-powered phishing detection and blockchain transaction simulation.

## Overview

The backend provides two main services:
1. **URL Classification** - ML models for phishing/malicious site detection
2. **Transaction Simulation** - EVM transaction analysis and risk detection

## Quick Start

### Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run

```bash
python app.py
```

The API will be available at `http://localhost:5000`

## API Endpoints

### URL Classification

- `POST /predict` - Classify a URL as benign or malicious
  ```json
  {
    "url": "https://example.com"
  }
  ```

- `GET /whois` - Get domain registration information
  ```json
  {
    "url": "https://example.com"
  }
  ```

### Transaction Simulation

- `POST /simulate` - Simulate a blockchain transaction
  ```json
  {
    "transaction": "0x...",
    "from": "0x...",
    "to": "0x..."
  }
  ```

### Wallet Management

- `GET /wallet` - Get wallet state and balances
- `POST /wallet/reset` - Reset wallet state
- `POST /wallet/swap` - Execute a token swap

### Model Metrics

- `GET /metrics` - Get comprehensive ML model evaluation metrics
  - Query params: `test_size` (number or "all"), `test_percentage` (0.0-1.0), `n_workers` (1-20)
- `GET /metrics/summary` - Quick metrics summary

## ML Models

### Model Architecture

CryptoC uses a **dual-model approach** for URL classification:

#### 1. HuggingFace Model (Primary)
- **Model**: `r3ddkahili/final-complete-malicious-url-model`
- **Type**: Pre-trained transformer model
- **Status**: ✅ Active (primary model)

**How it works:**
- Uses `transformers` library to load pre-trained model
- Returns labels as `LABEL_0`, `LABEL_1`, `LABEL_2`, `LABEL_3`
- Maps to `benign`/`malicious` based on score analysis
- If `LABEL_1` or `LABEL_3` probability > 0.05, classified as malicious

**Confusion Matrix Analysis (from evaluation on test set):**
- **True Positives (Blocked Phishing)**: 2,934
- **False Negatives (Missed Phishing)**: 66
- **False Positives (Wrongly Blocked)**: 144
- **True Negatives (Allowed Safe)**: 2,856

#### 2. XGBoost Model (Optional)
- **Type**: Custom trained XGBoost classifier
- **Location**: `backend/model/xgboost_model.pkl`
- **Status**: Optional (if trained, used as primary; otherwise HuggingFace is primary)

**Training:**
```bash
python train_xgboost.py
```

#### 3. Custom Scikit-learn Model (Fallback)
- **Type**: Custom scikit-learn model (joblib format)
- **Location**: `backend/model/` directory
- **Status**: Fallback only (requires model files)

**Files Required:**
- `model/model.pkl` - Trained classifier
- `model/vectorizer.pkl` - Text vectorizer (TF-IDF)
- `model/scaler.pkl` - Feature scaler

### Model Selection Logic

The prediction flow in `predict.py`:

1. **Try XGBoost first** (if available)
2. **Try HuggingFace model** (primary if XGBoost not available)
3. **Fallback to custom model** (if HuggingFace fails)
4. **Error handling** - If all fail, raises exception

### Model Evaluation

Evaluate models on test data:

```bash
# Evaluate on 20% of dataset with 10 parallel workers (default)
python evaluate_model.py

# Evaluate on specific number of samples
python evaluate_model.py --test_size 10000 --n_workers 10

# Evaluate on percentage of dataset
python evaluate_model.py --test_percentage 0.2 --n_workers 10

# Quick metrics summary
python show_metrics.py
```

## Dataset

- **Location**: `backend/data/urls.csv`
- **Total Instances**: 651,191 URLs
- **Label Distribution**:
  - Benign: 428,103 (65.74%)
  - Defacement: 96,457 (14.81%)
  - Phishing: 94,111 (14.45%)
  - Malware: 32,520 (4.99%)

## Project Structure

```
backend/
├── app.py                  # Main Flask application
├── predict.py              # ML model integration
├── hf_model.py            # HuggingFace model wrapper
├── blockchain_simulator.py # Transaction simulation engine
├── alchemy_simulator.py    # Alchemy RPC integration
├── wallet_manager.py      # Wallet state management
├── evaluate_model.py       # Model evaluation script
├── train_xgboost.py       # XGBoost training script
├── show_metrics.py        # Metrics display script
├── data/                  # ML training data
│   ├── urls.csv          # Main dataset
│   └── urls_features.csv  # Feature-extracted dataset
└── requirements.txt       # Python dependencies
```

## Dependencies

Key dependencies:
- `flask` - Web framework
- `transformers` - HuggingFace models
- `xgboost` - XGBoost ML model (optional)
- `scikit-learn` - ML utilities
- `pandas`, `numpy` - Data processing
- `web3` - Blockchain interaction

See `requirements.txt` for complete list.

## Development

### Running Tests

```bash
# Test URL prediction
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Get model metrics
curl http://localhost:5000/metrics?test_size=1000
```

### Training XGBoost Model

```bash
# Setup (first time)
./setup_xgboost.sh

# Train model
python train_xgboost.py
```

## Notes

- HuggingFace model is downloaded automatically on first use
- Model files (`.pkl`) are excluded from git (see `.gitignore`)
- Evaluation can use parallel processing for faster results
- Backend requires Python 3.8+

