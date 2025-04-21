import yaml
import re
import threading
import queue
import os

class RulesEngine:
    def __init__(self, packet_queue, alert_queue, rules_file=None):
        self.packet_queue = packet_queue
        self.alert_queue = alert_queue
        self.rules = []
        if rules_file and os.path.exists(rules_file):
            self.load_rules(rules_file)
        self.stop_processing_flag = threading.Event()
        self.processing_thread = None
        
    def start_processing(self):
        self.stop_processing_flag.clear()
        self.processing_thread = threading.Thread(target=self._process_queue)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
    def stop_processing(self):
        self.stop_processing_flag.set()
        if self.processing_thread:
            self.processing_thread.join(timeout=1.0)
            
    def load_rules(self, rules_file):
        """Load rules from YAML file"""
        try:
            with open(rules_file, 'r') as f:
                rule_defs = yaml.safe_load(f)
                
            self.rules = []
            for rule in rule_defs:
                # Compile regex patterns for performance
                if 'pattern' in rule:
                    rule['compiled_pattern'] = re.compile(rule['pattern'], re.IGNORECASE)
                self.rules.append(rule)
                
            print(f"Loaded {len(self.rules)} rules")
        except Exception as e:
            print(f"Error loading rules: {e}")
            
    def add_rule(self, rule):
        """Add a single rule programmatically"""
        if 'pattern' in rule:
            rule['compiled_pattern'] = re.compile(rule['pattern'], re.IGNORECASE)
        self.rules.append(rule)
        
    def _process_queue(self):
        """Main rule processing loop"""
        while not self.stop_processing_flag.is_set():
            try:
                packet_info = self.packet_queue.get(timeout=1.0)
                self._check_rules(packet_info)
                self.packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Rules engine error: {e}")
                
    def _check_rules(self, packet_info):
        """Check packet against defined rules"""
        raw_packet = packet_info.get('raw_packet')
        if not raw_packet:
            return
            
        for rule in self.rules:
            match = False
            
            # Check IP conditions if defined
            if 'src_ip' in rule and packet_info.get('src_ip'):
                if rule['src_ip'] != packet_info['src_ip']:
                    continue
                    
            if 'dst_ip' in rule and packet_info.get('dst_ip'):
                if rule['dst_ip'] != packet_info['dst_ip']:
                    continue
                    
            # Check protocol if defined
            if 'protocol' in rule and packet_info.get('protocol'):
                if rule['protocol'] != packet_info['protocol']:
                    continue
                    
            # Check for payload pattern match if defined
            if 'compiled_pattern' in rule and raw_packet.haslayer('Raw'):
                payload = raw_packet.getlayer('Raw').load
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if rule['compiled_pattern'].search(payload_str):
                        match = True
                    else:
                        continue
                except:
                    continue
                    
            # If all conditions met or pattern matched
            if match or ('compiled_pattern' not in rule):
                alert = {
                    'timestamp': packet_info['timestamp'],
                    'rule_id': rule.get('id', 'unknown'),
                    'alert_type': 'SIGNATURE',
                    'confidence': rule.get('confidence', 1.0),
                    'description': rule.get('description', 'Signature match'),
                    'src_ip': packet_info.get('src_ip'),
                    'dst_ip': packet_info.get('dst_ip'),
                    'protocol': packet_info.get('protocol')
                }
                
                self.alert_queue.put(alert)