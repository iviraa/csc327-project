#!/bin/bash

echo "🚀 Starting CryptoC Backend Server..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cd backend

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -q flask flask-cors eth-abi eth-utils python-whois 2>/dev/null

echo ""
echo "✅ Backend ready!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🌐 API Server: http://localhost:5000"
echo ""
echo "Available Endpoints:"
echo "  ML Safety:     POST /predict"
echo "  Simulation:    POST /simulate"
echo "  Wallet:        GET/POST /wallet/*"
echo ""
echo "Press Ctrl+C to stop the server"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Start Flask server
python app.py
