import os
import sys
import yaml
import queue
import time
import signal
import logging
import threading

# Add project directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.packet_capture import PacketCapture
from src.feature_extractor import FeatureExtractor
from src.ml_detection import MLDetectionEngine
from src.rules_engine import RulesEngine
from src.alert_system import AlertSystem
from src.api_service import IDSApiService

class IntrusionDetectionSystem:
    def __init__(self, config=None):
        self.config = config or {}
        self.interface = self.config.get('interface', 'eth0')
        self.model_path = self.config.get('model_path', 'models/ids_model.pkl')
        self.rules_file = self.config.get('rules_file', 'config/rules.yaml')
        self.alert_log_file = self.config.get('alert_log_file', 'logs/alerts.json')
        
        # Set up queues for inter-component communication
        self.packet_queue = queue.Queue()
        self.feature_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        
        # Create directories
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.alert_log_file), exist_ok=True)
        
        # Initialize components
        self.packet_capture = PacketCapture(
            interface=self.interface,
            packet_queue=self.packet_queue
        )
        
        # Initialize components with queues
        self.feature_extractor = FeatureExtractor(
            packet_queue=self.packet_queue,
            feature_queue=self.feature_queue
        )
        
        # Initialize ML detection engine
        self.ml_engine = MLDetectionEngine(
            feature_queue=self.feature_queue,
            alert_queue=self.alert_queue,
            model_path=self.model_path
        )
        
        # Initialize rules engine
        self.rules_engine = RulesEngine(
            packet_queue=self.packet_queue,
            alert_queue=self.alert_queue,
            rules_file=self.rules_file
        )

        ## Initialize alert system
        self.alert_system = AlertSystem(
            alert_queue=self.alert_queue,
            alert_log_file=self.alert_log_file
        )

        # Initialize API service
        self.api_service = IDSApiService(
            alert_queue=self.alert_queue,
            host=self.config.get('api_host', '0.0.0.0'),
            port=self.config.get('api_port', 5000)
        )
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename=self.config.get('log_file', 'logs/ids.log')
        )
        self.logger = logging.getLogger('IDS')

    # Start all components    
    def start(self):
        """Start all IDS components"""
        self.logger.info("Starting Intrusion Detection System...")
        
        # Start API service first
        self.api_service.start()
        
        # Start packet processing pipeline
        self.packet_capture.start_capture()
        self.feature_extractor.start_processing()
        self.ml_engine.start_detection()
        self.rules_engine.start_processing()
        self.alert_system.start_processing()
        
        self.logger.info(f"IDS started on interface {self.interface}")

    # Stop all components   
    def stop(self):
        """Stop all IDS components"""
        self.logger.info("Stopping Intrusion Detection System...")
        
        # Stop components in reverse order
        self.alert_system.stop_processing()
        self.rules_engine.stop_processing()
        self.ml_engine.stop_detection()
        self.feature_extractor.stop_processing()
        self.packet_capture.stop_capture()
        
        self.logger.info("IDS stopped")

    ## Run the IDS until interrupted
    def run(self):
        """Run the IDS until interrupted"""
        self.start()
        
        # Set up signal handlers for graceful shutdown
        def signal_handler(sig, frame):
            self.logger.info("Shutdown signal received")
            self.stop()
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

# Load configuration from YAML file
def load_config(config_path):
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}

# Main entry point
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Custom Intrusion Detection System')
    parser.add_argument('--config', default='config/config.yaml', help='Path to configuration file')
    parser.add_argument('--interface', help='Network interface to monitor')
    parser.add_argument('--mode', choices=['detection', 'learning'], default='detection', 
                      help='IDS operation mode')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Override with command line arguments
    if args.interface:
        config['interface'] = args.interface
    if args.mode == 'learning':
        config['learning_mode'] = True
    
    # Start the IDS
    ids = IntrusionDetectionSystem(config)
    ids.run()