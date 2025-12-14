from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-dashboard-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

class AlertStore:
    def __init__(self, max_alerts=None):
        # max_alerts: None => unlimited storage
        self.alerts = []
        self.max_alerts = max_alerts
        self.lock = threading.Lock()
    
    def add_alert(self, alert_type, src_ip, message):
        with self.lock:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert = {
                'timestamp': timestamp,
                'type': alert_type,
                'src_ip': src_ip,
                'message': message,
                'id': len(self.alerts)
            }
            self.alerts.append(alert)
            
            # Keep only recent alerts if a cap is configured
            if self.max_alerts is not None and len(self.alerts) > self.max_alerts:
                self.alerts = self.alerts[-self.max_alerts:]
            
            # Emit via WebSocket
            socketio.emit('new_alert', alert)
            print(f"[{timestamp}] {message}")
    
    def get_alerts(self, limit=None):
        with self.lock:
            if not self.alerts:
                return []
            if limit is None:
                return list(self.alerts)
            return self.alerts[-limit:]
    
    def get_stats(self):
        with self.lock:
            alerts_list = self.alerts
            stats = {
                'total_alerts': len(alerts_list),
                'alerts_last_hour': len([a for a in alerts_list 
                                       if self._is_recent(a['timestamp'], hours=1)]),
                'unique_ips': len(set(a['src_ip'] for a in alerts_list)),
                'alert_types': {}
            }
            
            for alert in alerts_list:
                alert_type = alert['type']
                stats['alert_types'][alert_type] = stats['alert_types'].get(alert_type, 0) + 1
            
            return stats
    
    def _is_recent(self, timestamp_str, hours=1):
        try:
            alert_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            return (datetime.now() - alert_time).total_seconds() < hours * 3600
        except:
            return False

# Initialize alert store
alert_store = AlertStore()

def get_blacklist():
    """Read blacklist file.
    Prefer `ids/blacklist.txt` if present (used by detectors), else fall back
    to top-level `blacklist.txt` for backwards compatibility.
    """
    candidates = [Path('ids') / 'blacklist.txt', Path('blacklist.txt')]
    for p in candidates:
        if p.exists():
            with open(p, 'r') as f:
                return [line.strip() for line in f if line.strip()]
    return []

def remove_from_blacklist(ip):
    """Remove IP from blacklist file (tries detector's file first)."""
    candidates = [Path('ids') / 'blacklist.txt', Path('blacklist.txt')]
    for p in candidates:
        if p.exists():
            with open(p, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            if ip in ips:
                ips.remove(ip)
                with open(p, 'w') as f:
                    for ip_addr in ips:
                        f.write(ip_addr + "\n")
                return True
    return False

# Flask Routes
@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts. If no limit query param is provided, return all stored alerts."""
    if 'limit' in request.args:
        limit = request.args.get('limit', type=int)
    else:
        limit = None
    return jsonify({'alerts': alert_store.get_alerts(limit)})

@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    """Clear all alerts"""
    with alert_store.lock:
        alert_store.alerts = []
    return jsonify({'success': True})

@app.route('/api/blacklist', methods=['GET', 'DELETE'])
def blacklist():
    """Get or remove from blacklist"""
    if request.method == 'GET':
        return jsonify({'blacklist': get_blacklist()})
    elif request.method == 'DELETE':
        ip = request.args.get('ip')
        if ip and remove_from_blacklist(ip):
            # Notify connected clients that blacklist changed
            try:
                socketio.emit('blacklist_update', {'blacklist': get_blacklist()})
            except Exception:
                pass
            return jsonify({'success': True})
        return jsonify({'success': False}), 400

@app.route('/api/stats')
def stats():
    """Get IDS statistics"""
    return jsonify(alert_store.get_stats())

# Background thread for periodic updates
def background_updater():
    """Periodically send updates to connected clients"""
    while True:
        time.sleep(5)  # Update every 5 seconds
        try:
            stats = alert_store.get_stats()
            socketio.emit('stats_update', {
                'blacklist_count': len(get_blacklist()),
                'recent_alerts': stats['alerts_last_hour'],
                'total_alerts': stats['total_alerts'],
                'unique_ips': stats['unique_ips'],
                'timestamp': datetime.now().strftime("%H:%M:%S")
            })
            # Also send the full blacklist so clients can stay in sync with file-based changes
            try:
                socketio.emit('blacklist_update', {'blacklist': get_blacklist()})
            except Exception:
                pass
        except Exception as e:
            print(f"Error in background updater: {e}")

# Start background thread
threading.Thread(target=background_updater, daemon=True).start()

if __name__ == '__main__':
    print("Starting IDS Web Dashboard on http://localhost:5000")
    print("WebSocket support: Enabled")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)