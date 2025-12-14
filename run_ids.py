#!/usr/bin/env python3
"""
Main runner for IDS with web frontend
"""
import threading
import time

# Import frontend components
from frontend.app import alert_store, socketio, app

# Import your actual IDS
from ids.main import IDS

class EnhancedIDS:
    """Wrapper that connects your IDS to the web frontend"""
    
    def __init__(self):
        # Initialize your actual IDS
        self.ids = IDS()
        
        # Store a reference to the original packet handler
        self.original_handler = self.ids.packet_handler
        
        # Create enhanced handler
        self.ids.packet_handler = self.enhanced_packet_handler
        
    def enhanced_packet_handler(self, pkt):
        """Enhanced packet handler"""
        try:
            # Call original handler
            self.original_handler(pkt)
        except Exception as e:
            print(f"Error in packet handler: {e}")
    
    def run(self, interface="eth0"):
        """Run the enhanced IDS"""
        print(f"Starting Enhanced IDS on interface: {interface}")
        try:
            self.ids.run(interface=interface)
        except Exception as e:
            print(f"IDS Error: {e}")

def start_frontend():
    """Start Flask web interface"""
    print("Starting Web Dashboard on http://localhost:5000")
    print("Press Ctrl+C to stop")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)

if __name__ == '__main__':
    print("=" * 50)
    print("IDS Dashboard with REAL Detection Engine")
    print("=" * 50)
    
    # Start frontend in a thread (non-blocking)
    frontend_thread = threading.Thread(
        target=start_frontend,
        daemon=True
    )
    frontend_thread.start()
    
    # Wait a moment for Flask to start
    time.sleep(3)
    
    # Start the enhanced IDS
    try:
        ids = EnhancedIDS()
        ids.run(interface="\\Device\\NPF_{2C8A903D-15B6-49B6-86D8-6992D5571166}")
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")