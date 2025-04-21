import numpy as np
from collections import defaultdict
import threading
import queue
import time
from datetime import datetime

class FeatureExtractor:
    def __init__(self, packet_queue, feature_queue, window_size=60):
        self.packet_queue = packet_queue
        self.feature_queue = feature_queue
        self.window_size = window_size  # Time window in seconds
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'intervals': [],
            'packet_sizes': []
        })
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
            
    def _process_queue(self):
        while not self.stop_processing_flag.is_set():
            try:
                packet_info = self.packet_queue.get(timeout=1.0)
                self._update_flow_stats(packet_info)
                self._generate_features()
                self.packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Feature extraction error: {e}")
                
    def _update_flow_stats(self, packet_info):
        # Create flow key (bidirectional)
        if packet_info['src_ip'] and packet_info['dst_ip']:
            # Sort IPs to make flow key bidirectional
            ips = sorted([packet_info['src_ip'], packet_info['dst_ip']])
            protocol = packet_info['protocol'] or 0
            flow_key = f"{ips[0]}_{ips[1]}_{protocol}"
            
            # Update flow statistics
            flow = self.flow_stats[flow_key]
            timestamp = datetime.fromisoformat(packet_info['timestamp'])
            
            if not flow['start_time']:
                flow['start_time'] = timestamp
            else:
                interval = (timestamp - flow['last_time']).total_seconds()
                flow['intervals'].append(interval)
                
            flow['packet_count'] += 1
            flow['byte_count'] += packet_info['length']
            flow['last_time'] = timestamp
            flow['packet_sizes'].append(packet_info['length'])
            
    def _generate_features(self):
        """Generate features for flows that have sufficient data"""
        current_time = datetime.now()
        features_batch = []
        
        for flow_key, stats in list(self.flow_stats.items()):
            if not stats['last_time']:
                continue
                
            # Skip flows that don't have enough data yet
            if stats['packet_count'] < 5:
                continue
                
            # Calculate time-based expiration
            if (current_time - stats['last_time']).total_seconds() > self.window_size:
                # Flow expired, generate features
                features = self._extract_flow_features(flow_key, stats)
                if features:
                    features_batch.append(features)
                # Remove the expired flow
                del self.flow_stats[flow_key]
                
        if features_batch:
            self.feature_queue.put(features_batch)
            
    def _extract_flow_features(self, flow_key, stats):
        """Extract ML features from a flow"""
        if stats['packet_count'] < 2:
            return None
            
        # Calculate statistical features
        packet_sizes = np.array(stats['packet_sizes'])
        if len(stats['intervals']) > 0:
            intervals = np.array(stats['intervals'])
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
        else:
            mean_interval = 0
            std_interval = 0
            
        duration = (stats['last_time'] - stats['start_time']).total_seconds()
        if duration > 0:
            packets_per_second = stats['packet_count'] / duration
            bytes_per_second = stats['byte_count'] / duration
        else:
            packets_per_second = 0
            bytes_per_second = 0
            
        # Create feature dictionary
        features = {
            'flow_key': flow_key,
            'timestamp': stats['last_time'].isoformat(),
            'packet_count': stats['packet_count'],
            'byte_count': stats['byte_count'],
            'duration': duration,
            'packets_per_second': packets_per_second,
            'bytes_per_second': bytes_per_second,
            'mean_packet_size': np.mean(packet_sizes),
            'std_packet_size': np.std(packet_sizes),
            'min_packet_size': np.min(packet_sizes),
            'max_packet_size': np.max(packet_sizes),
            'mean_interval': mean_interval,
            'std_interval': std_interval
        }
        
        return features