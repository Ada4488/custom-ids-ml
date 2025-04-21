from flask import Flask, request, jsonify
import threading
import json
import queue
import time
from datetime import datetime, timedelta

class IDSApiService:
    def __init__(self, alert_queue, host='0.0.0.0', port=5000):
        self.app = Flask(__name__)
        self.alert_queue = alert_queue
        self.host = host
        self.port = port
        self.server_thread = None
        self.recent_alerts = []
        self.max_alerts = 1000
        
        # Set up routes
        self._setup_routes()
        
    def _setup_routes(self):
        @self.app.route('/api/status', methods=['GET'])
        def status():
            return jsonify({
                'status': 'running',
                'time': datetime.now().isoformat(),
                'alert_count': len(self.recent_alerts)
            })
            
        @self.app.route('/api/alerts', methods=['GET'])
        def get_alerts():
            # Optional filtering
            alert_type = request.args.get('type')
            limit = request.args.get('limit', 100, type=int)
            since = request.args.get('since')
            
            filtered_alerts = self.recent_alerts
            
            if alert_type:
                filtered_alerts = [a for a in filtered_alerts if a.get('alert_type') == alert_type]
                
            if since:
                try:
                    since_dt = datetime.fromisoformat(since)
                    filtered_alerts = [
                        a for a in filtered_alerts 
                        if datetime.fromisoformat(a.get('timestamp', '')) >= since_dt
                    ]
                except ValueError:
                    pass
                    
            return jsonify({
                'alerts': filtered_alerts[-limit:],
                'total': len(filtered_alerts)
            })
            
        @self.app.route('/api/rules', methods=['POST'])
        def add_rule():
            # This would integrate with the RulesEngine
            rule = request.json
            if not rule:
                return jsonify({'error': 'No rule data provided'}), 400
                
            # Here we would add the rule to the engine
            return jsonify({'status': 'Rule added', 'rule_id': '12345'})
            
    def start(self):
        """Start the API server in a separate thread"""
        def run_server():
            self.app.run(host=self.host, port=self.port, debug=False)
            
        self.server_thread = threading.Thread(target=run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Start alert collection
        alert_thread = threading.Thread(target=self._collect_alerts)
        alert_thread.daemon = True
        alert_thread.start()
        
    def _collect_alerts(self):
        """Collect alerts from the queue to make them available via API"""
        while True:
            try:
                alert = self.alert_queue.get(timeout=1.0)
                self.recent_alerts.append(alert)
                
                # Trim if necessary
                if len(self.recent_alerts) > self.max_alerts:
                    self.recent_alerts = self.recent_alerts[-self.max_alerts:]
                    
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"API alert collection error: {e}")