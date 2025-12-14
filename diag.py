# diagnostic.py
import requests
import json
from datetime import datetime

def check_frontend_status():
    print("🔍 Checking frontend status...")
    
    # 1. Check if Flask is running
    try:
        resp = requests.get('http://localhost:5000/api/stats', timeout=5)
        print(f"✅ Flask server: RUNNING (HTTP {resp.status_code})")
        stats = resp.json()
        print(f"📊 Current stats: {stats}")
    except Exception as e:
        print(f"❌ Flask server: NOT RESPONDING ({e})")
        return
    
    # 2. Check WebSocket manually
    try:
        from websocket import create_connection
        ws = create_connection("ws://localhost:5000/socket.io/?EIO=4&transport=websocket")
        ws.send("2probe")
        response = ws.recv()
        print(f"✅ WebSocket: CONNECTED ({response})")
        ws.close()
    except ImportError:
        print("⚠️  websocket-client not installed, skipping WebSocket test")
        print("   Install: pip install websocket-client")
    except Exception as e:
        print(f"❌ WebSocket: CONNECTION FAILED ({e})")
    
    # 3. Check alerts endpoint
    try:
        resp = requests.get('http://localhost:5000/api/alerts')
        alerts = resp.json()['alerts']
        print(f"📝 Current alerts in store: {len(alerts)}")
        if alerts:
            print(f"   Latest: {alerts[-1]}")
    except Exception as e:
        print(f"❌ Alerts endpoint error: {e}")

if __name__ == '__main__':
    check_frontend_status()