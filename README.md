# Anosis Armour 🛡️

**AI-Powered Network Security Analysis Tool**

Anosis Armour uses machine learning to analyze network traffic captures (PCAP files) and detect security threats including DDoS attacks, port scans, brute force attempts, and suspicious network activity.

## 🚀 Quick Start

### Installation

```bash
# Install Anosis Armour
pip install anosis

# Or install from source
git clone https://github.com/mouazkass/anosis
cd anosis
pip install -r requirements.txt
```

### Basic Usage

```bash
# Analyze a PCAP file
anosis analyze capture.pcap

# Capture network traffic (requires sudo)
sudo anosis capture -i eth0 -o traffic.pcap

# Analyze with JSON output
anosis analyze suspicious.pcap --output json

# Save detailed report
anosis analyze traffic.pcap --save-report analysis.json
```

## 📊 What It Detects

- **DDoS Attacks** - Volumetric and protocol-based attacks
- **Port Scanning** - Horizontal and vertical port scans
- **Brute Force** - SSH, RDP, and other login attempts
- **Malware Activity** - Command & control communications
- **Data Exfiltration** - Unusual outbound data transfers
- **Suspicious Patterns** - Anomalous network behavior

## 💻 Commands

### `analyze` - Analyze PCAP Files

```bash
anosis analyze [OPTIONS] PCAP_FILE

Options:
  -o, --output [text|json]  Output format (default: text)
  -s, --save-report PATH    Save analysis report to file
  -v, --verbose            Show detailed analysis
```

**Example:**
```bash
$ anosis analyze capture.pcap

╔═══════════════════════════════════════════════════════════════╗
║     Anosis Armour - Network Security Analysis Tool v1.0       ║
╚═══════════════════════════════════════════════════════════════╝

[*] Loading PCAP file...
[✓] Loaded 5432 packets
[*] Analyzing network traffic...

┌──────────────────────────────────────────────────────────┐
│                    Analysis Summary                      │
├──────────────────────────────────────────────────────────┤
│  File: capture.pcap                                      │
│  Total Packets: 5432                                     │
│  Unique Flows: 87                                        │
│  Threats Detected: 2                                     │
│  Capture Duration: 300.5s                                │
│  Risk Score: 72/100                                      │
└──────────────────────────────────────────────────────────┘

[!] 2 Security Threats Detected:

╔══════════════════ THREAT DETECTED ══════════════════╗
║ Type: DDoS Attack                                   ║
║ Severity: HIGH                                      ║
║ Confidence: 87.3%                                   ║
║ Source: 192.168.1.105                               ║
║ Destination: 10.0.0.50                              ║
║ Port/Protocol: 80/TCP                               ║
╚═════════════════════════════════════════════════════╝
```

### `capture` - Capture Network Traffic

```bash
sudo anosis-armour capture [OPTIONS]

Options:
  -i, --interface TEXT    Network interface (default: eth0)
  -d, --duration INTEGER  Capture duration in seconds
  -o, --output PATH      Output PCAP file
  -f, --filter TEXT      BPF filter expression
```

**Examples:**
```bash
# Capture for 60 seconds
sudo anosis capture -i eth0 -d 60 -o minute.pcap

# Capture only HTTP traffic
sudo anosis capture -i eth0 --filter "tcp port 80" -o http.pcap

# Capture until interrupted (Ctrl+C)
sudo anosis capture -i eth0 -o capture.pcap
```

### `info` - System Information

```bash
anosis info
```

Shows detection capabilities, configuration paths, and usage examples.

## 📈 Understanding Results

### Risk Score (0-100)
- **0-20**: Low risk - Normal traffic patterns
- **21-50**: Medium risk - Some suspicious activity
- **51-80**: High risk - Likely security threats
- **81-100**: Critical - Active attacks detected

### Threat Severity
- **LOW**: Anomalous but likely benign
- **MEDIUM**: Potentially malicious, investigate
- **HIGH**: Likely attack, immediate action recommended
- **CRITICAL**: Active attack in progress

## 🔧 Working with tcpdump

Anosis Armour is designed to work seamlessly with tcpdump captures:

```bash
# Capture with tcpdump
sudo tcpdump -i eth0 -w capture.pcap -c 10000

# Analyze with Anosis Armour
anosis analyze capture.pcap
```

### Recommended tcpdump Filters

```bash
# Capture everything except SSH (to avoid capturing your own session)
sudo tcpdump -i eth0 -w capture.pcap 'not port 22'

# Capture only TCP traffic
sudo tcpdump -i eth0 -w capture.pcap 'tcp'

# Capture traffic to/from specific host
sudo tcpdump -i eth0 -w capture.pcap 'host 192.168.1.100'

# Capture HTTP and HTTPS traffic
sudo tcpdump -i eth0 -w capture.pcap 'tcp port 80 or tcp port 443'
```

## 📋 Output Formats

### Text Output (Default)
Human-readable format with colored output, threat boxes, and statistics.

### JSON Output
Machine-readable format for integration with other tools:

```json
{
  "file": "capture.pcap",
  "timestamp": "2024-01-15T10:30:00",
  "summary": {
    "total_packets": 5432,
    "unique_flows": 87,
    "threats_detected": 2,
    "duration": 300.5
  },
  "threats": [...],
  "statistics": {...},
  "risk_score": 72
}
```

## 🚨 Exit Codes

- `0`: No threats detected
- `1`: Threats detected (useful for scripting)

## 📝 Examples

### Automated Security Monitoring

```bash
#!/bin/bash
# Monitor network and alert on threats

# Capture 5 minutes of traffic
sudo tcpdump -i eth0 -w /tmp/capture.pcap -G 300 -W 1

# Analyze
if anosis analyze /tmp/capture.pcap; then
    echo "No threats detected"
else
    echo "ALERT: Threats detected!" | mail -s "Security Alert" admin@company.com
fi
```

### Continuous Monitoring

```bash
#!/bin/bash
# Continuous monitoring with hourly analysis

while true; do
    FILE="capture_$(date +%Y%m%d_%H%M%S).pcap"
    
    # Capture 1 hour
    sudo timeout 3600 tcpdump -i eth0 -w "$FILE"
    
    # Analyze and save report
    anosis analyze "$FILE" --save-report "report_$FILE.json"
    
    # Check if threats detected
    if [ $? -eq 1 ]; then
        # Send alert
        echo "Security threats detected in $FILE"
    fi
done
```

## ⚠️ Important Notes

1. **Permissions**: Packet capture requires root/sudo privileges
2. **Privacy**: Only analyze traffic on networks you own or have permission to monitor
3. **Performance**: Large PCAP files (>1GB) may take time to analyze
4. **Accuracy**: While highly accurate, always verify critical alerts manually

## 🐛 Troubleshooting

### "Permission denied" error
Always use `sudo` for packet capture:
```bash
sudo anosis capture -i eth0
```

### "No such device" error
Check available interfaces:
```bash
ip link show
# or
ifconfig
```

### Large PCAP files
For files over 1GB, consider splitting:
```bash
# Split into 100MB chunks
tcpdump -i eth0 -w capture.pcap -C 100
```

## 📧 Support

- GitHub Issues: https://github.com/security-team/anosis-armour/issues
- Email: mouazmoayad10@gmail.com

## 📄 License

MIT License - See LICENSE file for details.

---

**Anosis Armour** - Protecting networks with the power of AI
# Anosis
