#!/usr/bin/env python3
"""
Direct test of frontend connection
"""
import time
from datetime import datetime

# Import your frontend modules
try:
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from frontend.app import alert_store
    
    print("✅ Successfully imported alert_store")
    
    # Send test alerts
    for i in range(5):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = f"192.168.1.{i+100}"
        message = f"Test alert #{i+1}"
        
        print(f"Sending alert {i+1}: {message}")
        alert_store.add_alert('TEST', ip, message)
        
        time.sleep(1)
    
    print("\n✅ Check your frontend at http://localhost:5000")
    print("   You should see 5 test alerts!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()