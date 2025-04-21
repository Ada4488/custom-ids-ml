import json
import queue
import threading
import logging
import time
import os
from datetime import datetime

class AlertSystem:
    def __init__(self, alert_queue, alert_log_file=None, api_endpoint=None):
        self.alert_queue = alert_queue
        self.alert_log_file = alert_log_file
        self.api_endpoint = api_endpoint
        self.stop_processing_flag = threading.Event()
        self.processing_thread = None
        self.alert_handlers = []
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('IDS_Alert_System')
        
        # Configure file handler if specified
        if alert_log_file:
            os.makedirs(os.path.dirname(alert_log_file), exist_ok=True)
            file_handler = logging.FileHandler(alert_log_file)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(file_handler)
            
    def start_processing(self):
        self.stop_processing_flag.clear()
        self.processing_thread = threading.Thread(target=self._process_queue)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
    def stop_processing(self):
        self.stop_processing_flag.set()
        if self.processing_thread:
            self.processing_thread.join(timeout=1.0)
            
    def add_alert_handler(self, handler_func):
        """Add a custom alert handler function"""
        self.alert_handlers.append(handler_func)
        
    def _process_queue(self):
        """Main alert processing loop"""
        while not self.stop_processing_flag.is_set():
            try:
                alert = self.alert_queue.get(timeout=1.0)
                self._process_alert(alert)
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Alert processing error: {e}")
                
    def _process_alert(self, alert):
        """Process a single alert"""
        # Log the alert
        alert_type = alert.get('alert_type', 'UNKNOWN')
        description = alert.get('description', 'No description')
        
        self.logger.warning(f"ALERT: {alert_type} - {description}")
        
        # Add timestamp if not present
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().isoformat()
            
        # Write to JSON log file if configured
        if self.alert_log_file:
            try:
                with open(self.alert_log_file, 'a') as f:
                    f.write(json.dumps(alert) + "\n")
            except Exception as e:
                self.logger.error(f"Failed to write alert to log file: {e}")
                
        # Send to API endpoint if configured
        if self.api_endpoint:
            try:
                # This would use a library like requests
                # requests.post(self.api_endpoint, json=alert)
                pass
            except Exception as e:
                self.logger.error(f"Failed to send alert to API: {e}")
                
        # Call custom handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                self.logger.error(f"Custom alert handler error: {e}")