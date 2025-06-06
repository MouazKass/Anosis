# Anosis Armour

**ML-Based Network Security Monitoring Tool**

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)

Anosis Armour is an advanced network security monitoring tool that leverages machine learning algorithms to detect and classify network threats in real-time. Built with Python, it provides comprehensive analysis of network traffic patterns to identify potential security risks including DDoS attacks, port scans, malware communications, and data exfiltration attempts.

## 🚀 Features

### Core Capabilities
- **ML-Powered Threat Detection**: Advanced machine learning models using Isolation Forest and Random Forest algorithms
- **Real-time Analysis**: Analyze PCAP files with streaming support for large datasets
- **Behavioral Analysis**: Comprehensive feature extraction from network flows
- **Multi-format Output**: Export reports in JSON, CSV, and HTML formats
- **Interactive CLI**: User-friendly command-line interface with progress bars and colored output

### Threat Detection
- **DDoS Attacks**: High-volume traffic pattern detection
- **Port Scanning**: Systematic port enumeration identification
- **Brute Force Attacks**: Login attempt pattern recognition
- **Malware Communication**: Suspicious DNS tunneling and C&C detection
- **Data Exfiltration**: Large data transfer anomaly detection
- **Suspicious Activity**: General behavioral anomaly identification

### Technical Features
- **Streaming Analysis**: Handle large PCAP files (50MB+) efficiently
- **Flow-based Analysis**: Extract and analyze network conversation flows
- **Feature Engineering**: 28 comprehensive network features
- **Risk Scoring**: Calculate overall security risk scores (0-100)
- **Model Persistence**: Save and load trained ML models

## 📋 Requirements

### System Requirements
- Python 3.8 or higher
- Root privileges (for real-time monitoring)
- Minimum 4GB RAM
- 1GB free disk space

### Dependencies
```
click>=8.0.0
pandas>=1.3.0
numpy>=1.21.0
scikit-learn>=1.0.0
colorama>=0.4.4
tqdm>=4.62.0
scapy>=2.4.5
joblib>=1.1.0
```

## 🛠️ Installation

### Option 1: Install from Source
```bash
# Clone the repository
git clone https://github.com/mouazkass/anosis.git
cd anosis-armour

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x anosis_armour.py
```

### Option 2: Direct Installation
```bash
# Install dependencies
pip install click pandas numpy scikit-learn colorama tqdm scapy joblib

# Download the script
wget https://raw.githubusercontent.com/mouazkass/anosis/anosis_armour.py
chmod +x anosis_armour.py
```

## 🚀 Quick Start

### Basic PCAP Analysis
```bash
# Analyze a PCAP file
python anosis_armour.py analyze sample.pcap

# Save results to JSON
python anosis_armour.py analyze sample.pcap --output json --save report.json

# Generate HTML report
python anosis_armour.py analyze sample.pcap --output html --save report.html
```

### Training Custom Models
```bash
# Train ML models on synthetic data
python anosis_armour.py train
```

### Version Information
```bash
# Display version and system info
python anosis_armour.py version
```

## 📊 Usage Examples

### Example 1: Basic Threat Analysis
```bash
./anosis_armour.py analyze network_capture.pcap
```

**Output:**
```
┌──────────────────────────────────────────────────────┐
│                 Analysis Summary                     │
├──────────────────────────────────────────────────────┤
│  File: network_capture.pcap                          │
│  Total Packets: 15,420                               │
│  Unique Flows: 1,247                                 │
│  Threats Detected: 3                                 │
│  Capture Duration: 120.45s                           │
│  Risk Score: 35/100                                  │
└──────────────────────────────────────────────────────┘

🚨 HIGH - DDoS Attack
════════════════════════════════════════════════════════
   Source: 192.168.1.100:45123 → 203.0.113.50
   Protocol: TCP
   Confidence: 87.3%
   Timestamp: 2024-12-07T10:30:45
```

### Example 2: Large File Analysis with Streaming
```bash
./anosis_armour.py analyze large_capture.pcap --output json --save detailed_report.json
```

### Example 3: Multiple Output Formats
```bash
# Generate comprehensive reports
./anosis_armour.py analyze traffic.pcap --output html --save security_report.html
./anosis_armour.py analyze traffic.pcap --output csv --save threats.csv
```

## 🔧 Configuration

### Model Configuration
Models are automatically saved to `~/.anosis_armour/models/` after training. The tool includes:

- **Isolation Forest**: Anomaly detection with 10% contamination rate
- **Random Forest**: Classification with 100 estimators
- **Standard Scaler**: Feature normalization

### Feature Engineering
The ML engine extracts 28 network features:
- Packet-level statistics (count, size, timing)
- Flow-level metrics (duration, rates, ratios)
- Protocol analysis (TCP/UDP flags, ports)
- Behavioral indicators (entropy, patterns)

## 📈 Performance

### Benchmarks
- **Small files** (<50MB): Full memory analysis
- **Large files** (>50MB): Streaming analysis
- **Processing speed**: ~10,000 packets/second
- **Memory usage**: <2GB for most datasets
- **Detection accuracy**: 90%+ on synthetic data

### Optimization Tips
- Use streaming mode for files >50MB
- Limit analysis to 100k packets for very large files
- Close other applications during analysis
- Use SSD storage for better I/O performance

## 🛡️ Security Considerations

### Permissions
- Real-time monitoring requires root/administrator privileges
- PCAP analysis can run with user privileges
- Models are stored in user home directory

### Privacy
- No data is transmitted outside the local system
- PCAP files are processed locally
- Models can be trained on your own data

## 🐛 Troubleshooting

### Common Issues

**Issue**: `ModuleNotFoundError: No module named 'scapy'`
```bash
# Solution: Install scapy
pip install scapy
```

**Issue**: Permission denied for real-time monitoring
```bash
# Solution: Run with sudo
sudo python anosis_armour.py monitor
```

**Issue**: Out of memory with large PCAP files
```bash
# Solution: The tool automatically switches to streaming mode for files >50MB
# Manually enable streaming for smaller files that cause memory issues
```

**Issue**: No threats detected in known malicious traffic
```bash
# Solution: Retrain models with your specific data
python anosis_armour.py train
```

### Debug Mode
For verbose output, modify the logging level in the script:
```python
logging.basicConfig(level=logging.DEBUG)
```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Install development dependencies
4. Make changes and test
5. Submit a pull request

### Code Style
- Follow PEP 8 guidelines
- Use type hints where possible
- Add docstrings for functions
- Include unit tests for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
