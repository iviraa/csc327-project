#!/bin/bash

echo "🚀 Starting CryptoC Frontend..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if Python's http.server is available
if command -v python3 &> /dev/null; then
    echo "✅ Frontend ready!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🌐 Web Interface: http://localhost:8000"
    echo ""
    echo "Opening frontend/index.html in your browser..."
    echo "Make sure backend is running on http://localhost:5000"
    echo ""
    echo "Press Ctrl+C to stop the server"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    cd frontend
    python3 -m http.server 8000
else
    echo "⚠️  Python not found. Please open frontend/index.html directly in your browser."
    echo "Or install Python 3 to use the dev server."
fi
