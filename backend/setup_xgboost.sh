#!/bin/bash

# CryptoC XGBoost Model Setup Script
# This script sets up the XGBoost model for phishing detection

set -e

echo "=================================="
echo "CryptoC XGBoost Model Setup"
echo "=================================="
echo ""

# Check if virtual environment is activated
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "⚠️  Virtual environment not activated!"
    echo "Please run: source venv/bin/activate"
    exit 1
fi

echo "✓ Virtual environment detected: $VIRTUAL_ENV"
echo ""

# Check if XGBoost is installed
echo "Checking dependencies..."
if python -c "import xgboost" 2>/dev/null; then
    echo "✓ XGBoost is installed"
else
    echo "Installing XGBoost..."
    pip install xgboost==2.1.3
fi

# Check if dataset exists
if [ ! -f "data/urls.csv" ]; then
    echo ""
    echo "❌ Dataset not found!"
    echo "Expected: data/urls.csv"
    echo ""
    echo "Please download the dataset from:"
    echo "https://www.kaggle.com/datasets/manusiddhartha/malicious-urls-dataset"
    echo ""
    echo "Or use the existing dataset if available."
    exit 1
fi

echo "✓ Dataset found: data/urls.csv"

# Check dataset size
LINES=$(wc -l < data/urls.csv)
echo "  Dataset contains $LINES URLs"
echo ""

# Check if model already exists
if [ -f "model/xgboost_model.pkl" ]; then
    echo "⚠️  Existing XGBoost model found!"
    echo ""
    read -p "Do you want to retrain the model? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Using existing model."
        echo ""
        echo "To use the model, just start the backend:"
        echo "  python app.py"
        exit 0
    fi
fi

# Train the model
echo ""
echo "=================================="
echo "Training XGBoost Model"
echo "=================================="
echo ""
echo "This may take 10-20 minutes depending on your system..."
echo "Training on $LINES URLs"
echo ""

python train_xgboost.py

# Check if training was successful
if [ -f "model/xgboost_model.pkl" ]; then
    echo ""
    echo "=================================="
    echo "✓ Setup Complete!"
    echo "=================================="
    echo ""
    echo "Model files created:"
    echo "  - model/xgboost_model.pkl"
    echo "  - model/vectorizer.pkl"
    echo "  - model/scaler.pkl"
    echo ""
    echo "Next steps:"
    echo "  1. (Optional) Set Alchemy API key for transaction simulation:"
    echo "     export ALCHEMY_API_KEY='your-key-here'"
    echo ""
    echo "  2. Start the backend:"
    echo "     python app.py"
    echo ""
    echo "  3. Test the model:"
    echo "     curl -X POST http://localhost:5000/predict \\"
    echo "       -H 'Content-Type: application/json' \\"
    echo "       -d '{\"url\": \"https://app.uniswap.org\"}'"
    echo ""
else
    echo ""
    echo "❌ Training failed!"
    echo "Check the error messages above."
    exit 1
fi


