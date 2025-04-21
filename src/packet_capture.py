from scapy.all import sniff
import pandas as pd
from datetime import datetime
import threading
import queue

# PacketCapture class for capturing network packets
# This class uses Scapy to sniff packets on a specified network interface
# and processes them to extract basic features.
# It runs in a separate thread and can be started and stopped as needed.
# The captured packets are put into a queue for further processing by other components
# of the IDS.
# The class also handles exceptions that may occur during packet capture
class PacketCapture:
    # Capture network packets using Scapy
    def __init__(self, interface="eth0", packet_queue=None):
        self.interface = interface
        self.packet_queue = packet_queue or queue.Queue()
        self.stop_capture_flag = threading.Event()
        self.capture_thread = None
    # Start the packet capture in a separate thread    
    def start_capture(self):
        self.stop_capture_flag.clear()
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
    # Stop the packet capture   
    def stop_capture(self):
        self.stop_capture_flag.set()
        if self.capture_thread:
            self.capture_thread.join(timeout=1.0)
    # Check if the capture thread is alive        
    def _capture_packets(self):
        try:
            sniff(iface=self.interface, prn=self._process_packet, store=0, 
                  stop_filter=lambda _: self.stop_capture_flag.is_set())
        except Exception as e:
            print(f"Packet capture error: {e}")
    # Process each captured packet        
    def _process_packet(self, packet):
        packet_info = self._extract_basic_features(packet)
        self.packet_queue.put(packet_info)
    # Extract basic features from the packet    
    def _extract_basic_features(self, packet):
        # Basic extraction - will be expanded in feature engineering
        features = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'length': len(packet),
            'raw_packet': packet
        }
        
        # Extract IP layer info if present
        if packet.haslayer('IP'):
            features['src_ip'] = packet['IP'].src
            features['dst_ip'] = packet['IP'].dst
            features['protocol'] = packet['IP'].proto
            
        return features