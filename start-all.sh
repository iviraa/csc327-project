#!/bin/bash

echo "🚀 Starting CryptoC - Full Stack"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "This will start both backend and frontend servers"
echo "in separate terminal windows."
echo ""

# Check if we're in a terminal that supports opening new tabs
if command -v gnome-terminal &> /dev/null; then
    echo "Opening backend in new terminal tab..."
    gnome-terminal --tab --title="CryptoC Backend" -- bash -c "./start-backend.sh; exec bash"

    sleep 2

    echo "Opening frontend in new terminal tab..."
    gnome-terminal --tab --title="CryptoC Frontend" -- bash -c "./start-frontend.sh; exec bash"

elif command -v xterm &> /dev/null; then
    echo "Opening backend in new terminal..."
    xterm -T "CryptoC Backend" -e "./start-backend.sh" &

    sleep 2

    echo "Opening frontend in new terminal..."
    xterm -T "CryptoC Frontend" -e "./start-frontend.sh" &

else
    echo "⚠️  Could not detect terminal emulator."
    echo ""
    echo "Please run these commands in separate terminal windows:"
    echo ""
    echo "Terminal 1:  ./start-backend.sh"
    echo "Terminal 2:  ./start-frontend.sh"
    echo ""
    echo "Or start them in the background:"
    ./start-backend.sh &
    BACKEND_PID=$!
    sleep 3
    ./start-frontend.sh &
    FRONTEND_PID=$!

    echo ""
    echo "✅ Both servers started!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🌐 Backend:  http://localhost:5000"
    echo "🌐 Frontend: http://localhost:5173"
    echo ""
    echo "PIDs: Backend=$BACKEND_PID Frontend=$FRONTEND_PID"
    echo ""
    echo "Press Ctrl+C to stop all servers"

    trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT
    wait
fi
