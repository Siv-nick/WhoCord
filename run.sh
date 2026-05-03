#!/bin/bash
# WhoCord Launcher – starts web dashboard and stays alive until Flask exits
cd "$(dirname "$0")"
source venv/bin/activate

# Start Flask in the background, capture its PID
python3 web_app.py &
FLASK_PID=$!

# Wait a moment for the server to start, then open the browser
sleep 2
xdg-open http://127.0.0.1:5000 2>/dev/null

# Keep the script running until Flask stops (so the dashboard stays alive)
wait $FLASK_PID
