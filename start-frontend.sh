#!/bin/bash

echo "🚀 Starting CryptoC Frontend..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if Python's http.server is available
if ! command -v python3 &> /dev/null; then
    echo "⚠️  Python not found. Please open frontend/index.html directly in your browser."
    echo "Or install Python 3 to use the dev server."
    exit 1
fi

# Check if port 8000 is already in use and kill existing frontend server
# Try multiple methods to find the process
PID=""

# Method 1: Try lsof
if command -v lsof &> /dev/null; then
    PID=$(lsof -ti :8000 2>/dev/null)
fi

# Method 2: Try fuser
if [ -z "$PID" ] && command -v fuser &> /dev/null; then
    PID=$(fuser 8000/tcp 2>/dev/null | awk '{print $1}')
fi

# Method 3: Use ps and grep to find python http.server on port 8000
if [ -z "$PID" ]; then
    PID=$(ps aux | grep -E "python.*http.server.*8000" | grep -v grep | awk '{print $2}' | head -1)
fi

if [ ! -z "$PID" ]; then
    # Check if it's a Python process
    if ps -p $PID -o comm= 2>/dev/null | grep -q python; then
        echo "⚠️  Found existing frontend server (PID: $PID). Stopping it..."
        kill $PID 2>/dev/null
        sleep 2
        # Verify it's dead
        if ps -p $PID > /dev/null 2>&1; then
            echo "Force killing process..."
            kill -9 $PID 2>/dev/null
            sleep 1
        fi
        echo "✅ Old server stopped. Starting new one..."
    else
        echo "⚠️  Port 8000 is in use by a different process (PID: $PID)"
        echo "Frontend may already be running at http://localhost:8000"
        exit 0
    fi
fi

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
