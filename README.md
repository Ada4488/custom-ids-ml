
# Custom Intrusion Detection System (IDS) with Machine Learning

## Overview

This project implements a lightweight, real-time Intrusion Detection System that uses both machine learning and signature-based approaches to detect network threats. The system analyzes network traffic, extracts features, and identifies potential attacks using anomaly detection and predefined rules.

## Features

- Real-time packet capture and analysis
- Machine learning-based anomaly detection
- Rule-based signature detection
- REST API for integration with other security tools
- Dashboard integration with ELK Stack/Grafana
- Containerized deployment with Docker

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Access to a network interface for packet capturing
- Python 3.8+ (for development)

### Quick Deployment

1. Clone the repository:
   ```bash
   git clone https://github.com/Ada4488/custom-ids-ml.git
   cd custom-ids-ml
   ```

2. Configure the system (optional):
   - Edit `config/config.yaml` to configure interfaces and parameters
   - Modify `config/rules.yaml` to add custom detection rules

3. Start the IDS system:
   ```bash
   docker-compose up -d
   ```

4. Access the dashboard:
   - Kibana: http://localhost:5601
   - Grafana: http://localhost:3000

## System Components

### 1. Network Traffic Capture (`PacketCapture`)

This component interfaces with the network to capture raw packets:
- Uses Scapy for packet capture
- Runs in its own thread to avoid blocking
- Extracts basic packet information and forwards it to the feature extractor

```python
# Example usage
capture = PacketCapture(interface="eth0", packet_queue=queue.Queue())
capture.start_capture()
```

### 2. Feature Extraction (`FeatureExtractor`)

Transforms raw network packets into machine learning-ready features:
- Aggregates packets into flows (connections)
- Calculates statistical features like packet sizes, intervals, etc.
- Uses time windows to process network traffic in batches

```python
# Features extracted include:
# - Flow duration
# - Packets per second
# - Bytes per second
# - Statistical measures of packet sizes and timing
```

### 3. ML Detection Engine (`MLDetectionEngine`)

The core anomaly detection component:
- Uses Isolation Forest algorithm to detect anomalous network flows
- Can be trained on normal traffic to establish a baseline
- Automatically improves as it collects more data
- Outputs alerts for detected anomalies

```python
# ML model uses these key techniques:
# - Unsupervised learning (no labeled data required)
# - Standard scaling of features 
# - Anomaly scoring based on isolation depth
```

### 4. Rules Engine (`RulesEngine`)

Provides traditional signature-based detection:
- Uses YAML rules definition format
- Can match on IP addresses, protocols, and payload patterns
- Complements the ML engine for known attack detection

Example rule format:
```yaml
- id: "SQL_INJECTION_1"
  description: "SQL Injection attempt"
  protocol: 6  # TCP
  pattern: "SELECT.*FROM.*WHERE"
  confidence: 0.8
```

### 5. Alert System (`AlertSystem`)

Manages alerts from both detection engines:
- Logs alerts to file and console
- Supports custom alert handlers for integration
- Forwards alerts to the API service

### 6. API Service (`IDSApiService`)

Provides REST API for integration and monitoring:
- Exposes system status and alerts
- Allows rule management via API calls
- Enables integration with external security tools

## Dashboard Setup

The system integrates with ELK Stack (Elasticsearch, Logstash, Kibana) for visualization:

1. Alerts are sent to Elasticsearch
2. Kibana provides visualization and exploration
3. Sample dashboards are included in `dashboards/`

## Customization

### Adding Custom Rules

Create or edit rules in `config/rules.yaml`:

```yaml
- id: "CUSTOM_RULE_1"
  description: "My custom detection rule"
  src_ip: "192.168.1.100"  # Optional source IP
  dst_ip: "10.0.0.1"       # Optional destination IP
  protocol: 17             # UDP (17)
  pattern: "malicious pattern"
  confidence: 0.9
```

### Training on Your Network

To improve detection:

1. Run the system in learning mode:
   ```bash
   python main.py --mode=learning
   ```

2. Let it collect normal traffic for at least 24 hours
3. The model will automatically save and be used for detection

## Using the API

Examples of API usage:

```bash
# Get system status
curl http://localhost:5000/api/status

# Get recent alerts
curl http://localhost:5000/api/alerts?limit=10

# Add a new rule
curl -X POST -H "Content-Type: application/json" \
  -d '{"id":"CUSTOM_API_RULE","description":"API added rule","pattern":"evil pattern"}' \
  http://localhost:5000/api/rules
```

## Security Considerations

- The system requires access to raw network packets
- Run in an isolated environment if possible
- Review and tune rules regularly to reduce false positives
- Keep the system updated with the latest threat signatures

## Advanced Usage

### Integration with SIEM

The IDS can forward alerts to external SIEM systems:

```python
# Add a SIEM forwarding handler
def forward_to_siem(alert):
    requests.post("https://siem.example.com/api/events", json=alert)

alert_system.add_alert_handler(forward_to_siem)
```

### Running on Cloud Providers

For deployment on cloud infrastructure:

1. Configure network mirroring/tapping on your cloud provider
2. Deploy the IDS using the provided Docker configuration
3. Adjust network settings based on your cloud environment

## Troubleshooting

Common issues and solutions:

1. **No packets captured**
   - Check interface name and permissions
   - Ensure the container has network access

2. **High false positive rate**
   - Run longer in learning mode
   - Adjust the contamination parameter in the ML model
   - Add exclusion rules for normal traffic patterns

3. **Performance issues**
   - Increase the sampling rate
   - Adjust the feature window size
   - Scale horizontally with multiple instances

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- NSL-KDD and CICIDS2017 datasets for initial model validation
- Open source security tools that inspired this project
