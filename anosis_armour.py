#!/usr/bin/env python3
"""
Anosis Armour - ML-Based Network Security Monitoring Tool
Advanced threat detection using machine learning and behavioral analysis
"""

import click
import sys
import os
import json
import logging
from datetime import datetime
from pathlib import Path
import colorama
from colorama import Fore, Style
import pandas as pd
import numpy as np
from typing import Optional, Dict, List, Tuple
import joblib
import warnings
import base64
import pickle
from collections import defaultdict
import time
from tqdm import tqdm
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import hashlib

warnings.filterwarnings('ignore')

# Initialize colorama for cross-platform color support
colorama.init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('anosis_armour')

# Version info
VERSION = "1.0.0"
AUTHOR = "MMK SECURITY"

# Default paths
HOME_DIR = Path.home()
ANOSIS_DIR = HOME_DIR / '.anosis_armour'
ANOSIS_DIR.mkdir(exist_ok=True)

class ThreatAlert:
    """Represents a detected security threat"""
    def __init__(self, timestamp, threat_type, severity, confidence, 
                 source_ip, dest_ip, port, protocol, details):
        self.timestamp = timestamp
        self.threat_type = threat_type
        self.severity = severity
        self.confidence = confidence
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.port = port
        self.protocol = protocol
        self.details = details

class MLThreatDetector:
    """Advanced ML-based threat detection engine"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.anomaly_detector = None
        self.classifier = None
        self.is_trained = False
        self.feature_names = [
            'packet_count', 'byte_count', 'duration', 'avg_packet_size',
            'packets_per_second', 'bytes_per_second', 'avg_iat', 'std_iat',
            'tcp_ratio', 'udp_ratio', 'src_port', 'dst_port',
            'unique_dst_ports', 'unique_src_ports', 'syn_count', 'ack_count',
            'fin_count', 'rst_count', 'psh_count', 'urg_count',
            'small_packet_ratio', 'large_packet_ratio', 'port_class',
            'is_dns', 'is_http', 'is_https', 'is_ssh', 'packet_size_entropy'
        ]
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models with pre-trained weights or defaults"""
        # Initialize Isolation Forest for anomaly detection
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # Initialize Random Forest for classification
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )
        
        # Load or create training data
        self._load_or_train_models()
    
    def _load_or_train_models(self):
        """Load pre-trained models or train on synthetic data"""
        model_path = ANOSIS_DIR / 'models' / 'threat_detector.pkl'
        
        if model_path.exists():
            try:
                with open(model_path, 'rb') as f:
                    saved_models = pickle.load(f)
                    self.anomaly_detector = saved_models['anomaly']
                    self.classifier = saved_models['classifier']
                    self.scaler = saved_models['scaler']
                    self.is_trained = True
                    click.echo(f"{Fore.GREEN}[✓] Loaded ML models{Style.RESET_ALL}")
                    return
            except:
                pass
        
        # Train on synthetic data if no saved model
        click.echo(f"{Fore.YELLOW}[*] Training ML models on synthetic data...{Style.RESET_ALL}")
        self._train_on_synthetic_data()
    
    def _train_on_synthetic_data(self):
        """Train models on synthetic network data"""
        # Generate synthetic training data
        n_samples = 10000
        
        # Normal traffic
        normal_data = self._generate_normal_traffic(n_samples // 2)
        
        # Attack traffic
        attack_data = []
        attack_types = [
            self._generate_ddos_traffic,
            self._generate_port_scan_traffic,
            self._generate_dns_tunnel_traffic,
            self._generate_data_exfil_traffic
        ]
        
        samples_per_attack = n_samples // (2 * len(attack_types))
        for attack_gen in attack_types:
            attack_data.append(attack_gen(samples_per_attack))
        
        # Combine data
        X_normal = np.array(normal_data)
        X_attack = np.vstack(attack_data)
        
        X = np.vstack([X_normal, X_attack])
        y = np.array([0] * len(normal_data) + [1] * len(X_attack))
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train anomaly detector on normal traffic only
        self.anomaly_detector.fit(X_scaled[:len(normal_data)])
        
        # Train classifier on all data
        self.classifier.fit(X_scaled, y)
        
        self.is_trained = True
        
        # Save models
        self._save_models()
    
    def _generate_normal_traffic(self, n_samples):
        """Generate synthetic normal traffic features"""
        features = []
        for _ in range(n_samples):
            feature = [
                np.random.poisson(50),  # packet_count
                np.random.normal(50000, 20000),  # byte_count
                np.random.exponential(10),  # duration
                np.random.normal(1000, 200),  # avg_packet_size
                np.random.normal(5, 2),  # packets_per_second
                np.random.normal(5000, 2000),  # bytes_per_second
                np.random.exponential(0.2),  # avg_iat
                np.random.exponential(0.1),  # std_iat
                np.random.beta(8, 2),  # tcp_ratio
                np.random.beta(2, 8),  # udp_ratio
                np.random.randint(1024, 65535),  # src_port
                np.random.choice([80, 443, 22, 3306, 8080]),  # dst_port
                np.random.poisson(5),  # unique_dst_ports
                np.random.poisson(3),  # unique_src_ports
                np.random.poisson(2),  # syn_count
                np.random.poisson(40),  # ack_count
                np.random.poisson(2),  # fin_count
                np.random.poisson(0.1),  # rst_count
                np.random.poisson(10),  # psh_count
                np.random.poisson(0.01),  # urg_count
                np.random.beta(2, 8),  # small_packet_ratio
                np.random.beta(2, 8),  # large_packet_ratio
                np.random.choice([0, 1, 2]),  # port_class
                0,  # is_dns
                np.random.choice([0, 1]),  # is_http
                np.random.choice([0, 1]),  # is_https
                0,  # is_ssh
                np.random.uniform(0.5, 0.9)  # packet_size_entropy
            ]
            features.append(feature)
        return features
    
    def _generate_ddos_traffic(self, n_samples):
        """Generate synthetic DDoS traffic features"""
        features = []
        for _ in range(n_samples):
            feature = [
                np.random.poisson(10000),  # very high packet_count
                np.random.normal(1000000, 100000),  # high byte_count
                np.random.exponential(1),  # short duration
                np.random.choice([64, 128, 256]),  # small avg_packet_size
                np.random.normal(10000, 1000),  # very high packets_per_second
                np.random.normal(100000, 10000),  # high bytes_per_second
                np.random.exponential(0.0001),  # very low avg_iat
                np.random.exponential(0.00005),  # very low std_iat
                1.0,  # all TCP
                0.0,  # no UDP
                np.random.randint(1024, 65535),  # random src_port
                np.random.choice([80, 443]),  # web dst_port
                1,  # single target
                np.random.poisson(1000),  # many sources
                np.random.poisson(8000),  # many syn
                np.random.poisson(100),  # few ack
                0,  # no fin
                np.random.poisson(50),  # some rst
                0,  # no psh
                0,  # no urg
                0.9,  # mostly small packets
                0.1,  # few large packets
                0,  # well-known port
                0,  # not DNS
                1,  # is_http
                0,  # not https
                0,  # not ssh
                np.random.uniform(0.1, 0.3)  # low entropy
            ]
            features.append(feature)
        return np.array(features)
    
    def _generate_port_scan_traffic(self, n_samples):
        """Generate synthetic port scan traffic features"""
        features = []
        for _ in range(n_samples):
            feature = [
                np.random.poisson(200),  # moderate packet_count
                np.random.normal(12800, 1000),  # small byte_count
                np.random.exponential(30),  # longer duration
                64,  # min packet size
                np.random.normal(10, 2),  # steady packets_per_second
                np.random.normal(640, 100),  # low bytes_per_second
                np.random.uniform(0.1, 1),  # regular avg_iat
                np.random.uniform(0.01, 0.1),  # low std_iat
                1.0,  # all TCP
                0.0,  # no UDP
                np.random.randint(40000, 50000),  # high src_port
                np.random.randint(1, 65535),  # scanning all ports
                np.random.poisson(100),  # many unique_dst_ports
                1,  # single source
                np.random.poisson(200),  # many syn
                0,  # no ack
                0,  # no fin
                np.random.poisson(150),  # many rst
                0,  # no psh
                0,  # no urg
                1.0,  # all small packets
                0.0,  # no large packets
                np.random.choice([0, 1, 2]),  # various port classes
                0,  # not DNS
                0,  # not http
                0,  # not https
                0,  # not ssh
                np.random.uniform(0.0, 0.2)  # very low entropy
            ]
            features.append(feature)
        return np.array(features)
    
    def _generate_dns_tunnel_traffic(self, n_samples):
        """Generate synthetic DNS tunneling traffic features"""
        features = []
        for _ in range(n_samples):
            feature = [
                np.random.poisson(1000),  # high packet_count for DNS
                np.random.normal(100000, 20000),  # unusual byte_count for DNS
                np.random.exponential(60),  # sustained duration
                np.random.normal(200, 50),  # larger DNS packets
                np.random.normal(20, 5),  # steady packets_per_second
                np.random.normal(4000, 1000),  # high bytes_per_second for DNS
                np.random.exponential(0.05),  # regular avg_iat
                np.random.exponential(0.02),  # low std_iat
                0.0,  # no TCP
                1.0,  # all UDP
                np.random.randint(1024, 65535),  # random src_port
                53,  # DNS port
                1,  # single DNS server
                np.random.poisson(10),  # multiple sources
                0,  # no syn (UDP)
                0,  # no ack (UDP)
                0,  # no fin (UDP)
                0,  # no rst (UDP)
                0,  # no psh (UDP)
                0,  # no urg (UDP)
                0.3,  # some small packets
                0.3,  # some large packets (unusual for DNS)
                0,  # well-known port
                1,  # is_dns
                0,  # not http
                0,  # not https
                0,  # not ssh
                np.random.uniform(0.7, 0.95)  # high entropy (encrypted data)
            ]
            features.append(feature)
        return np.array(features)
    
    def _generate_data_exfil_traffic(self, n_samples):
        """Generate synthetic data exfiltration traffic features"""
        features = []
        for _ in range(n_samples):
            feature = [
                np.random.poisson(500),  # moderate packet_count
                np.random.normal(5000000, 1000000),  # very high byte_count
                np.random.exponential(120),  # long duration
                np.random.normal(10000, 2000),  # large avg_packet_size
                np.random.normal(5, 1),  # steady packets_per_second
                np.random.normal(50000, 10000),  # high bytes_per_second
                np.random.exponential(0.2),  # regular avg_iat
                np.random.exponential(0.1),  # moderate std_iat
                0.9,  # mostly TCP
                0.1,  # some UDP
                np.random.randint(1024, 65535),  # random src_port
                np.random.choice([443, 22, 3389]),  # encrypted channels
                np.random.poisson(3),  # few unique_dst_ports
                1,  # single source
                np.random.poisson(5),  # few syn
                np.random.poisson(450),  # many ack
                np.random.poisson(5),  # few fin
                np.random.poisson(1),  # few rst
                np.random.poisson(200),  # many psh (data transfer)
                np.random.poisson(0.1),  # few urg
                0.1,  # few small packets
                0.8,  # mostly large packets
                np.random.choice([0, 1]),  # various ports
                0,  # not DNS
                0,  # not http
                1,  # is_https (encrypted)
                0,  # not ssh
                np.random.uniform(0.8, 0.99)  # high entropy (encrypted/compressed)
            ]
            features.append(feature)
        return np.array(features)
    
    def extract_features(self, flow_packets):
        """Extract comprehensive features from packet flow"""
        if not flow_packets:
            return np.zeros(len(self.feature_names))
        
        try:
            from scapy.all import TCP, UDP, IP, DNS
        except ImportError:
            return np.zeros(len(self.feature_names))
        
        # Basic statistics
        packet_count = len(flow_packets)
        packet_sizes = [len(bytes(p)) for p in flow_packets]
        byte_count = sum(packet_sizes)
        
        # Time-based features
        timestamps = [float(p.time) for p in flow_packets]
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.001
        
        if len(timestamps) > 1:
            iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            avg_iat = np.mean(iats)
            std_iat = np.std(iats)
        else:
            avg_iat = 0
            std_iat = 0
        
        # Rate features
        packets_per_second = packet_count / max(duration, 0.001)
        bytes_per_second = byte_count / max(duration, 0.001)
        
        # Size features
        avg_packet_size = np.mean(packet_sizes)
        small_packet_ratio = sum(1 for s in packet_sizes if s < 100) / packet_count
        large_packet_ratio = sum(1 for s in packet_sizes if s > 1000) / packet_count
        
        # Calculate packet size entropy
        size_counts = defaultdict(int)
        for size in packet_sizes:
            size_counts[size // 100] += 1  # Group by 100-byte bins
        
        total = sum(size_counts.values())
        entropy = 0
        for count in size_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p)
        
        packet_size_entropy = entropy / np.log2(len(size_counts)) if len(size_counts) > 1 else 0
        
        # Protocol features
        tcp_count = sum(1 for p in flow_packets if TCP in p)
        udp_count = sum(1 for p in flow_packets if UDP in p)
        tcp_ratio = tcp_count / packet_count
        udp_ratio = udp_count / packet_count
        
        # Port features
        src_ports = set()
        dst_ports = set()
        src_port = 0
        dst_port = 0
        
        for p in flow_packets:
            if TCP in p:
                src_ports.add(p[TCP].sport)
                dst_ports.add(p[TCP].dport)
                if src_port == 0:
                    src_port = p[TCP].sport
                    dst_port = p[TCP].dport
            elif UDP in p:
                src_ports.add(p[UDP].sport)
                dst_ports.add(p[UDP].dport)
                if src_port == 0:
                    src_port = p[UDP].sport
                    dst_port = p[UDP].dport
        
        unique_src_ports = len(src_ports)
        unique_dst_ports = len(dst_ports)
        
        # Port classification
        if dst_port < 1024:
            port_class = 0  # Well-known
        elif dst_port < 49152:
            port_class = 1  # Registered
        else:
            port_class = 2  # Dynamic
        
        # Service detection
        is_dns = 1 if dst_port == 53 else 0
        is_http = 1 if dst_port == 80 else 0
        is_https = 1 if dst_port == 443 else 0
        is_ssh = 1 if dst_port == 22 else 0
        
        # TCP flags (if TCP)
        syn_count = 0
        ack_count = 0
        fin_count = 0
        rst_count = 0
        psh_count = 0
        urg_count = 0
        
        for p in flow_packets:
            if TCP in p:
                flags = p[TCP].flags
                if flags & 0x02: syn_count += 1  # SYN
                if flags & 0x10: ack_count += 1  # ACK
                if flags & 0x01: fin_count += 1  # FIN
                if flags & 0x04: rst_count += 1  # RST
                if flags & 0x08: psh_count += 1  # PSH
                if flags & 0x20: urg_count += 1  # URG
        
        # Compile features
        features = [
            packet_count, byte_count, duration, avg_packet_size,
            packets_per_second, bytes_per_second, avg_iat, std_iat,
            tcp_ratio, udp_ratio, src_port, dst_port,
            unique_dst_ports, unique_src_ports, syn_count, ack_count,
            fin_count, rst_count, psh_count, urg_count,
            small_packet_ratio, large_packet_ratio, port_class,
            is_dns, is_http, is_https, is_ssh, packet_size_entropy
        ]
        
        return np.array(features)
    
    def predict_threat(self, features):
        """Predict if traffic is malicious and classify threat type"""
        if not self.is_trained:
            # Fallback to rule-based if models not trained
            return self._rule_based_detection(features)
        
        # Scale features
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # Anomaly detection
        anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
        is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
        
        # Classification probability
        threat_prob = self.classifier.predict_proba(features_scaled)[0][1]
        
        # Determine threat type based on features
        threat_type = self._classify_threat_type(features, anomaly_score, threat_prob)
        
        # Calculate confidence
        if is_anomaly and threat_prob > 0.7:
            confidence = min(0.95, (threat_prob + abs(anomaly_score) / 10) / 2)
        elif is_anomaly or threat_prob > 0.5:
            confidence = max(0.5, threat_prob)
        else:
            confidence = 0.0
            threat_type = 0  # Normal
        
        return threat_type, confidence
    
    def _classify_threat_type(self, features, anomaly_score, threat_prob):
        """Classify specific threat type based on features"""
        if threat_prob < 0.5 and anomaly_score > -0.1:
            return 0  # Normal
        
        # Extract key features
        packet_count = features[0]
        packets_per_second = features[4]
        syn_count = features[14]
        unique_dst_ports = features[12]
        is_dns = features[23]
        packet_size_entropy = features[27]
        
        # DDoS detection
        if packets_per_second > 1000 and syn_count > packet_count * 0.7:
            return 1  # DDoS
        
        # Port scan detection
        if unique_dst_ports > 50 and syn_count > packet_count * 0.8:
            return 2  # Port scan
        
        # DNS tunneling detection
        if is_dns and packet_size_entropy > 0.8 and packet_count > 100:
            return 4  # Malware/DNS tunnel
        
        # Data exfiltration detection
        if features[1] > 1000000 and packet_size_entropy > 0.7:  # High bytes + high entropy
            return 5  # Data exfiltration
        
        # Brute force detection
        if features[11] in [22, 3389, 21] and packet_count > 100:
            return 3  # Brute force
        
        # Generic suspicious activity
        if anomaly_score < -0.5 or threat_prob > 0.7:
            return 6  # Suspicious activity
        
        return 0  # Normal
    
    def _rule_based_detection(self, features):
        """Fallback rule-based detection"""
        packet_count = features[0]
        packets_per_second = features[4]
        dst_port = features[11]
        is_dns = features[23]
        
        # Simple rules
        if packets_per_second > 1000:
            return 1, 0.8  # DDoS
        elif packet_count > 100 and is_dns:
            return 4, 0.7  # DNS anomaly
        elif dst_port in [22, 3389] and packet_count > 100:
            return 3, 0.6  # Brute force
        elif packet_count > 500:
            return 6, 0.5  # Suspicious
        
        return 0, 0.0  # Normal
    
    def _save_models(self):
        """Save trained models"""
        model_path = ANOSIS_DIR / 'models'
        model_path.mkdir(exist_ok=True)
        
        with open(model_path / 'threat_detector.pkl', 'wb') as f:
            pickle.dump({
                'anomaly': self.anomaly_detector,
                'classifier': self.classifier,
                'scaler': self.scaler
            }, f)

class NetworkAnalyzer:
    """Core network traffic analyzer"""
    
    def __init__(self):
        self.ml_detector = MLThreatDetector()
        self.threat_types = {
            0: "Normal Traffic",
            1: "DDoS Attack",
            2: "Port Scan",
            3: "Brute Force Attack",
            4: "Malware Communication",
            5: "Data Exfiltration",
            6: "Suspicious Activity"
        }
        
    def analyze_pcap(self, pcap_file: Path) -> Dict:
        """Analyze a PCAP file and return threat analysis"""
        try:
            from scapy.all import rdpcap, sniff, PcapReader, IP, TCP, UDP, DNS, ICMP
        except ImportError:
            click.echo(f"{Fore.RED}Error: scapy not installed. Run: pip install scapy{Style.RESET_ALL}")
            sys.exit(1)
            
        results = {
            'file': str(pcap_file),
            'timestamp': datetime.now().isoformat(),
            'summary': {},
            'threats': [],
            'statistics': {},
            'risk_score': 0
        }
        
        # Check file size
        file_size = pcap_file.stat().st_size / (1024 * 1024)  # MB
        click.echo(f"{Fore.CYAN}[*] Analyzing PCAP file ({file_size:.1f} MB)...{Style.RESET_ALL}")
        
        # For large files, use streaming approach
        if file_size > 50:  # If larger than 50MB
            click.echo(f"{Fore.YELLOW}[!] Large file detected, using streaming analysis...{Style.RESET_ALL}")
            return self._analyze_pcap_streaming(pcap_file)
        
        # Regular analysis for smaller files
        click.echo(f"{Fore.CYAN}[*] Loading PCAP file...{Style.RESET_ALL}")
        
        # Use progress bar for loading
        try:
            # First, count packets
            packet_count = sum(1 for _ in PcapReader(str(pcap_file)))
            
            # Then load with progress bar
            packets = []
            with tqdm(total=packet_count, desc="Loading packets", unit="pkt", 
                     bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]') as pbar:
                for packet in PcapReader(str(pcap_file)):
                    packets.append(packet)
                    pbar.update(1)
            
        except FileNotFoundError:
            click.echo(f"{Fore.RED}[!] Error: File not found: {pcap_file}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            click.echo(f"{Fore.RED}[!] Error reading PCAP: {e}{Style.RESET_ALL}")
            click.echo(f"{Fore.YELLOW}[!] Trying streaming mode...{Style.RESET_ALL}")
            return self._analyze_pcap_streaming(pcap_file)
            
        total_packets = len(packets)
        click.echo(f"{Fore.GREEN}[✓] Loaded {total_packets} packets{Style.RESET_ALL}")
        
        if total_packets == 0:
            click.echo(f"{Fore.YELLOW}[!] Warning: PCAP file is empty{Style.RESET_ALL}")
            return results
        
        # Continue with regular analysis...
        return self._analyze_packets(packets, results)
    
    def _analyze_pcap_streaming(self, pcap_file: Path) -> Dict:
        """Analyze large PCAP files using streaming"""
        from scapy.all import PcapReader, IP, TCP, UDP, DNS
        
        results = {
            'file': str(pcap_file),
            'timestamp': datetime.now().isoformat(),
            'summary': {},
            'threats': [],
            'statistics': {},
            'risk_score': 0
        }
        
        flows = defaultdict(list)
        packet_count = 0
        threat_alerts = []
        
        click.echo(f"{Fore.CYAN}[*] Streaming analysis in progress...{Style.RESET_ALL}")
        
        try:
            # Progress bar for streaming
            with tqdm(desc="Analyzing packets", unit="pkt", 
                     bar_format='{l_bar}{bar}| {n_fmt} [{elapsed}<{remaining}]') as pbar:
                
                with PcapReader(str(pcap_file)) as pcap_reader:
                    for packet in pcap_reader:
                        packet_count += 1
                        pbar.update(1)
                        
                        # Extract flow key
                        if IP in packet:
                            if TCP in packet:
                                flow_key = (packet[IP].src, packet[IP].dst, 
                                          packet[TCP].sport, packet[TCP].dport, 'TCP')
                            elif UDP in packet:
                                flow_key = (packet[IP].src, packet[IP].dst,
                                          packet[UDP].sport, packet[UDP].dport, 'UDP')
                            else:
                                flow_key = (packet[IP].src, packet[IP].dst, 0, 0, 'OTHER')
                            
                            flows[flow_key].append(packet)
                            
                            # Analyze flows periodically to avoid memory issues
                            if len(flows[flow_key]) >= 100:
                                # Analyze this flow
                                features = self.ml_detector.extract_features(flows[flow_key])
                                threat_type, confidence = self.ml_detector.predict_threat(features)
                                
                                if threat_type != 0:
                                    alert = self._create_alert(flows[flow_key][:10], threat_type, confidence)
                                    threat_alerts.append(alert)
                                
                                # Keep only recent packets to save memory
                                flows[flow_key] = flows[flow_key][-10:]
                        
                        # Limit analysis for very large files
                        if packet_count >= 100000:
                            pbar.set_description("Reached 100k packet limit")
                            break
                
        except Exception as e:
            click.echo(f"\n{Fore.RED}[!] Error during streaming analysis: {e}{Style.RESET_ALL}")
        
        # Analyze remaining flows
        click.echo(f"\n{Fore.CYAN}[*] Analyzing {len(flows)} flows...{Style.RESET_ALL}")
        
        with tqdm(total=len(flows), desc="Processing flows", unit="flow") as pbar:
            for flow_key, flow_packets in flows.items():
                if len(flow_packets) > 10:  # Only analyze significant flows
                    features = self.ml_detector.extract_features(flow_packets)
                    threat_type, confidence = self.ml_detector.predict_threat(features)
                    
                    if threat_type != 0:
                        alert = self._create_alert(flow_packets[:10], threat_type, confidence)
                        threat_alerts.append(alert)
                pbar.update(1)
        
        # Update results
        results['summary'] = {
            'total_packets': packet_count,
            'unique_flows': len(flows),
            'threats_detected': len(threat_alerts),
            'duration': 'Unknown (streaming mode)'
        }
        
        results['threats'] = [self._alert_to_dict(alert) for alert in threat_alerts]
        results['risk_score'] = self._calculate_risk_score(threat_alerts, packet_count)
        
        # Basic statistics
        results['statistics'] = {
            'analysis_mode': 'streaming',
            'packets_analyzed': packet_count,
            'flows_found': len(flows)
        }
        
        return results
    
    def _analyze_packets(self, packets, results):
        """Analyze loaded packets"""
        from scapy.all import IP, TCP, UDP
        
        click.echo(f"{Fore.CYAN}[*] Extracting network flows...{Style.RESET_ALL}")
        
        # Extract flows with progress bar
        flows = defaultdict(list)
        with tqdm(total=len(packets), desc="Extracting flows", unit="pkt") as pbar:
            for packet in packets:
                if IP in packet:
                    if TCP in packet:
                        flow_key = (packet[IP].src, packet[IP].dst, 
                                  packet[TCP].sport, packet[TCP].dport, 'TCP')
                    elif UDP in packet:
                        flow_key = (packet[IP].src, packet[IP].dst,
                                  packet[UDP].sport, packet[UDP].dport, 'UDP')
                    else:
                        flow_key = (packet[IP].src, packet[IP].dst, 0, 0, 'OTHER')
                    
                    flows[flow_key].append(packet)
                pbar.update(1)
        
        click.echo(f"{Fore.GREEN}[✓] Found {len(flows)} unique network flows{Style.RESET_ALL}")
        
        threat_alerts = []
        
        # Analyze flows with progress bar
        click.echo(f"{Fore.CYAN}[*] Running ML threat detection...{Style.RESET_ALL}")
        
        with tqdm(total=len(flows), desc="Analyzing flows", unit="flow") as pbar:
            for flow_id, flow_packets in flows.items():
                # Extract features using ML detector
                features = self.ml_detector.extract_features(flow_packets)
                
                # Predict threat
                threat_type, confidence = self.ml_detector.predict_threat(features)
                
                if threat_type != 0:  # Not normal traffic
                    alert = self._create_alert(flow_packets, threat_type, confidence)
                    threat_alerts.append(alert)
                
                pbar.update(1)
        
        click.echo(f"{Fore.GREEN}[✓] ML analysis complete{Style.RESET_ALL}")
        
        # Calculate statistics
        results['summary'] = {
            'total_packets': len(packets),
            'unique_flows': len(flows),
            'threats_detected': len(threat_alerts),
            'duration': self._calculate_capture_duration(packets)
        }
        
        results['threats'] = [self._alert_to_dict(alert) for alert in threat_alerts]
        results['statistics'] = self._calculate_statistics(packets, flows)
        results['risk_score'] = self._calculate_risk_score(threat_alerts, len(packets))
        
        return results
    
    def _extract_flows(self, packets):
        """Extract network flows from packets"""
        try:
            from scapy.all import IP, TCP, UDP
        except ImportError:
            return {}
            
        flows = defaultdict(list)
        
        for packet in packets:
            if IP in packet:
                if TCP in packet:
                    flow_key = (packet[IP].src, packet[IP].dst, 
                               packet[TCP].sport, packet[TCP].dport)
                elif UDP in packet:
                    flow_key = (packet[IP].src, packet[IP].dst,
                               packet[UDP].sport, packet[UDP].dport)
                else:
                    flow_key = (packet[IP].src, packet[IP].dst, 0, 0)
                
                flows[flow_key].append(packet)
        
        return flows
    
    def _create_alert(self, packets, threat_type, confidence):
        """Create a threat alert from suspicious traffic"""
        try:
            from scapy.all import IP, TCP, UDP
        except ImportError:
            pass
            
        first_packet = packets[0]
        
        # Extract IPs
        src_ip = first_packet[IP].src if IP in first_packet else "Unknown"
        dst_ip = first_packet[IP].dst if IP in first_packet else "Unknown"
        
        # Extract ports
        if TCP in first_packet:
            port = first_packet[TCP].dport
            protocol = "TCP"
        elif UDP in first_packet:
            port = first_packet[UDP].dport
            protocol = "UDP"
        else:
            port = 0
            protocol = "Other"
        
        # Determine severity
        severity = self._calculate_severity(confidence, threat_type)
        
        # Additional details
        details = {
            'packet_count': len(packets),
            'total_bytes': sum(len(bytes(p)) for p in packets),
            'duration': float(packets[-1].time - packets[0].time) if len(packets) > 1 else 0,
            'first_seen': datetime.fromtimestamp(float(packets[0].time)).isoformat(),
            'last_seen': datetime.fromtimestamp(float(packets[-1].time)).isoformat()
        }
        
        return ThreatAlert(
            timestamp=datetime.now().isoformat(),
            threat_type=self.threat_types[threat_type],
            severity=severity,
            confidence=confidence,
            source_ip=src_ip,
            dest_ip=dst_ip,
            port=port,
            protocol=protocol,
            details=details
        )
    
    def _alert_to_dict(self, alert):
        """Convert ThreatAlert to dictionary"""
        return {
            'timestamp': alert.timestamp,
            'threat_type': alert.threat_type,
            'severity': alert.severity,
            'confidence': f"{alert.confidence:.1%}",
            'source': f"{alert.source_ip}:{alert.port}" if alert.port else alert.source_ip,
            'destination': alert.dest_ip,
            'protocol': alert.protocol,
            'details': alert.details
        }
    
    def _calculate_severity(self, confidence, threat_type):
        """Calculate threat severity based on confidence and type"""
        if threat_type in [1, 4, 5]:  # DDoS, Malware, Data Exfil
            if confidence > 0.8:
                return "CRITICAL"
            elif confidence > 0.6:
                return "HIGH"
            else:
                return "MEDIUM"
        elif threat_type in [2, 3]:  # Port Scan, Brute Force
            if confidence > 0.8:
                return "HIGH"
            elif confidence > 0.6:
                return "MEDIUM"
            else:
                return "LOW"
        else:  # Suspicious Activity
            if confidence > 0.8:
                return "MEDIUM"
            else:
                return "LOW"
    
    def _calculate_capture_duration(self, packets):
        """Calculate total capture duration"""
        if len(packets) < 2:
            return 0
        
        start_time = float(packets[0].time)
        end_time = float(packets[-1].time)
        duration = end_time - start_time
        
        return f"{duration:.2f}s"
    
    def _calculate_statistics(self, packets, flows):
        """Calculate detailed network statistics"""
        try:
            from scapy.all import IP, TCP, UDP
        except ImportError:
            return {}
            
        stats = {
            'protocols': defaultdict(int),
            'top_talkers': defaultdict(int),
            'top_services': defaultdict(int),
            'packet_sizes': []
        }
        
        for packet in packets[:10000]:  # Limit for performance
            if IP in packet:
                stats['top_talkers'][packet[IP].src] += 1
                
                if TCP in packet:
                    stats['protocols']['TCP'] += 1
                    stats['top_services'][packet[TCP].dport] += 1
                elif UDP in packet:
                    stats['protocols']['UDP'] += 1
                    stats['top_services'][packet[UDP].dport] += 1
                else:
                    stats['protocols']['Other'] += 1
                
                stats['packet_sizes'].append(len(packet))
        
        # Convert to regular dict and get top entries
        return {
            'protocols': dict(stats['protocols']),
            'top_talkers': dict(sorted(stats['top_talkers'].items(), 
                                     key=lambda x: x[1], reverse=True)[:5]),
            'top_services': dict(sorted(stats['top_services'].items(), 
                                      key=lambda x: x[1], reverse=True)[:5]),
            'avg_packet_size': np.mean(stats['packet_sizes']) if stats['packet_sizes'] else 0
        }
    
    def _calculate_risk_score(self, threat_alerts, total_packets):
        """Calculate overall risk score (0-100)"""
        if not threat_alerts:
            return 0
        
        score = 0
        severity_weights = {
            'CRITICAL': 30,
            'HIGH': 20,
            'MEDIUM': 10,
            'LOW': 5
        }
        
        for alert in threat_alerts:
            score += severity_weights.get(alert.severity, 5)
        
        # Factor in threat density
        threat_density = len(threat_alerts) / max(total_packets, 1) * 1000
        score += min(threat_density * 10, 20)
        
        return min(int(score), 100)

def display_banner():
    """Display the Anosis Armour banner"""
    banner = f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║       █████╗ ███╗   ██╗ ██████╗ ███████╗██╗███████╗                      ║
║      ██╔══██╗████╗  ██║██╔═══██╗██╔════╝██║██╔════╝                      ║
║      ███████║██╔██╗ ██║██║   ██║███████╗██║███████╗                      ║
║      ██╔══██║██║╚██╗██║██║   ██║╚════██║██║╚════██║                      ║
║      ██║  ██║██║ ╚████║╚██████╔╝███████║██║███████║                      ║
║      ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝╚══════╝                      ║
║                                                                          ║
║           █████╗ ██████╗ ███╗   ███╗ ██████╗ ██╗   ██╗██████╗            ║
║          ██╔══██╗██╔══██╗████╗ ████║██╔═══██╗██║   ██║██╔══██╗           ║
║          ███████║██████╔╝██╔████╔██║██║   ██║██║   ██║██████╔╝           ║
║          ██╔══██║██╔══██╗██║╚██╔╝██║██║   ██║██║   ██║██╔══██╗           ║
║          ██║  ██║██║  ██║██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║  ██║           ║
║          ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝           ║
║                                                                          ║
║           ML-Based Network Security Monitoring Tool v1.0                 ║
║                               By: MMK SECURITY SOLUTIONS                 ║
╚══════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    click.echo(banner)

def format_threat_alert(threat):
    """Format a threat alert for display"""
    severity_colors = {
        'CRITICAL': Fore.RED,
        'HIGH': Fore.YELLOW,
        'MEDIUM': Fore.MAGENTA,
        'LOW': Fore.CYAN
    }
    
    color = severity_colors.get(threat['severity'], Fore.WHITE)
    
    click.echo(f"\n{color}{'='*60}")
    click.echo(f"🚨 {threat['severity']} - {threat['threat_type']}")
    click.echo(f"{'='*60}{Style.RESET_ALL}")
    
    click.echo(f"   Source: {threat['source']} → {threat['destination']}")
    click.echo(f"   Protocol: {threat['protocol']}")
    click.echo(f"   Confidence: {threat['confidence']}")
    click.echo(f"   Timestamp: {threat['timestamp']}")
    
    if threat['details']:
        click.echo(f"   Details:")
        for key, value in threat['details'].items():
            click.echo(f"      - {key}: {value}")

def display_summary(results):
    """Display analysis summary"""
    summary = results['summary']
    
    click.echo(f"\n{Fore.CYAN}┌{'─'*58}┐")
    click.echo(f"│{' '*20}Analysis Summary{' '*22}│")
    click.echo(f"├{'─'*58}┤")
    click.echo(f"│  File: {results['file'][:47]:<47} │")
    click.echo(f"│  Total Packets: {summary['total_packets']:<41}│")
    click.echo(f"│  Unique Flows: {summary['unique_flows']:<42}│")
    click.echo(f"│  Threats Detected: {summary['threats_detected']:<38}│")
    click.echo(f"│  Capture Duration: {summary['duration']:<38}│")
    click.echo(f"│  Risk Score: {results['risk_score']}/100{' '*36} │")
    click.echo(f"└{'─'*58}┘{Style.RESET_ALL}")

@click.group()
def cli():
    """Anosis Armour - ML-Based Network Security Monitoring Tool"""
    pass

@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Choice(['json', 'csv', 'html']), 
              help='Output format')
@click.option('--save', '-s', type=click.Path(), help='Save report to file')
def analyze(pcap_file, output, save):
    """Analyze a PCAP file for security threats"""
    display_banner()
    
    # Initialize analyzer
    analyzer = NetworkAnalyzer()
    
    # Analyze PCAP file
    pcap_path = Path(pcap_file)
    results = analyzer.analyze_pcap(pcap_path)
    
    # Display results
    display_summary(results)
    
    if results['threats']:
        click.echo(f"\n{Fore.RED}[!] {len(results['threats'])} Security Threats Detected:{Style.RESET_ALL}")
        for threat in results['threats']:
            format_threat_alert(threat)
    else:
        click.echo(f"\n{Fore.GREEN}[✓] No threats detected{Style.RESET_ALL}")
    
    # Save report if requested
    if save:
        save_path = Path(save)
        if output == 'json':
            with open(save_path, 'w') as f:
                json.dump(results, f, indent=2)
        elif output == 'csv':
            df = pd.DataFrame(results['threats'])
            df.to_csv(save_path, index=False)
        elif output == 'html':
            generate_html_report(results, save_path)
        
        click.echo(f"\n{Fore.GREEN}[✓] Report saved to: {save_path}{Style.RESET_ALL}")

@cli.command()
def monitor():
    """Real-time network monitoring (requires root)"""
    display_banner()
    click.echo(f"{Fore.YELLOW}[!] Real-time monitoring coming soon...{Style.RESET_ALL}")

@cli.command()
def train():
    """Train ML models on custom data"""
    display_banner()
    click.echo(f"{Fore.CYAN}[*] Training ML models...{Style.RESET_ALL}")
    
    detector = MLThreatDetector()
    click.echo(f"{Fore.GREEN}[✓] Models trained and saved{Style.RESET_ALL}")

@cli.command()
def version():
    """Display version information"""
    display_banner()
    click.echo(f"\nAnosis Armour v{VERSION}")
    click.echo(f"Author: {AUTHOR}")
    click.echo(f"ML Engine: Enabled")
    click.echo(f"Models Path: {ANOSIS_DIR / 'models'}")

def generate_html_report(results, save_path):
    """Generate HTML report"""
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Anosis Armour Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; }}
            .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; }}
            .threat {{ border: 1px solid #e74c3c; margin: 10px 0; padding: 15px; }}
            .critical {{ background: #e74c3c; color: white; }}
            .high {{ background: #f39c12; }}
            .medium {{ background: #9b59b6; color: white; }}
            .low {{ background: #3498db; color: white; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Anosis Armour Security Report</h1>
            <p>Generated: {datetime.now().isoformat()}</p>
        </div>
        
        <div class="summary">
            <h2>Analysis Summary</h2>
            <p>File: {results['file']}</p>
            <p>Total Packets: {results['summary']['total_packets']}</p>
            <p>Threats Detected: {results['summary']['threats_detected']}</p>
            <p>Risk Score: {results['risk_score']}/100</p>
        </div>
        
        <h2>Detected Threats</h2>
    """
    
    for threat in results['threats']:
        html_template += f"""
        <div class="threat {threat['severity'].lower()}">
            <h3>{threat['threat_type']}</h3>
            <p>Severity: {threat['severity']}</p>
            <p>Source: {threat['source']} → {threat['destination']}</p>
            <p>Confidence: {threat['confidence']}</p>
        </div>
        """
    
    html_template += """
    </body>
    </html>
    """
    
    with open(save_path, 'w') as f:
        f.write(html_template)

if __name__ == '__main__':
    cli()
