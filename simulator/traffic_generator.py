import random
import time
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import os
import sys

# Add project root to sys.path if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

class TrafficGenerator:
    """
    Synthetic Network Traffic Generator for Academic Intrusion Detection Demonstration.
    Generates realistic network flow records for NORMAL and ATTACK patterns without using actual exploits or malicious packets.
    """
    
    def __init__(self):
        self.internal_ips = [f"192.168.1.{i}" for i in range(10, 200)]
        self.external_ips = [f"10.0.0.{i}" for i in range(5, 50)] + [f"172.16.0.{i}" for i in range(10, 30)] + ["8.8.8.8", "1.1.1.1"]
        self.attacker_ips = ["192.168.1.250", "45.33.32.156", "185.220.101.5", "198.51.100.44"]
        
        self.common_ports = {
            'HTTP': 80,
            'HTTPS': 443,
            'DNS': 53,
            'SSH': 22,
            'RDP': 3389,
            'FTP': 21,
            'SMTP': 25,
            'MYSQL': 3306
        }

    def generate_single_flow(self, attack_type=None, timestamp=None):
        """
        Generate a single network flow record.
        If attack_type is None, randomly chooses based on realistic network distribution.
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if attack_type is None:
            # Distribution: 70% Normal, 10% Port Scan, 10% DoS, 10% Brute Force
            attack_type = random.choices(
                ['NORMAL', 'PORT_SCAN', 'DOS', 'BRUTE_FORCE'],
                weights=[0.70, 0.10, 0.10, 0.10]
            )[0]

        if attack_type == 'NORMAL':
            protocol = random.choices(['TCP', 'UDP', 'ICMP'], weights=[0.65, 0.30, 0.05])[0]
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.external_ips)
            src_port = random.randint(1024, 65535)
            
            if protocol == 'UDP':
                dst_port = 53
            elif protocol == 'ICMP':
                dst_port = 0
            else:
                dst_port = random.choice([80, 443, 22, 8080])

            packet_count = random.randint(5, 80)
            total_bytes = random.randint(500, 65000)
            connection_duration = round(random.uniform(0.5, 15.0), 3)
            failed_connections = random.choices([0, 1], weights=[0.98, 0.02])[0]
            connection_rate = round(random.uniform(0.5, 8.0), 2)

        elif attack_type == 'PORT_SCAN':
            protocol = random.choices(['TCP', 'UDP'], weights=[0.85, 0.15])[0]
            src_ip = random.choice(self.attacker_ips)
            dst_ip = random.choice(self.external_ips[:5])
            src_port = random.randint(30000, 60000)
            dst_port = random.randint(1, 65535)  # Scanning arbitrary ports

            packet_count = random.randint(1, 4)
            total_bytes = random.randint(40, 240)
            connection_duration = round(random.uniform(0.001, 0.15), 3)
            failed_connections = random.randint(1, 3)
            connection_rate = round(random.uniform(35.0, 250.0), 2)

        elif attack_type == 'DOS':
            protocol = random.choices(['TCP', 'UDP'], weights=[0.70, 0.30])[0]
            src_ip = random.choice(self.attacker_ips)
            dst_ip = "10.0.0.20"  # Target server
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 8080])

            packet_count = random.randint(1500, 25000)
            total_bytes = random.randint(200000, 15000000)
            connection_duration = round(random.uniform(0.05, 3.0), 3)
            failed_connections = random.randint(0, 5)
            connection_rate = round(random.uniform(150.0, 800.0), 2)

        elif attack_type == 'BRUTE_FORCE':
            protocol = 'TCP'
            src_ip = random.choice(self.attacker_ips)
            dst_ip = "10.0.0.15"  # Target auth server
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([22, 3389, 21, 80])  # SSH, RDP, FTP, HTTP

            packet_count = random.randint(12, 120)
            total_bytes = random.randint(1200, 15000)
            connection_duration = round(random.uniform(0.2, 4.0), 3)
            failed_connections = random.randint(6, 45)  # High failed connection attempts
            connection_rate = round(random.uniform(20.0, 75.0), 2)

        # Derived fields
        avg_packet_size = round(total_bytes / max(1, packet_count), 2)
        packets_per_sec = round(packet_count / max(0.001, connection_duration), 2)
        bytes_per_sec = round(total_bytes / max(0.001, connection_duration), 2)

        return {
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "average_packet_size": avg_packet_size,
            "connection_duration": connection_duration,
            "packets_per_second": packets_per_sec,
            "bytes_per_second": bytes_per_sec,
            "failed_connections": failed_connections,
            "connection_rate": connection_rate,
            "label": attack_type
        }

    def generate_dataset(self, num_samples=1600, output_file=None):
        """
        Generate a synthetic dataset with balanced classes for ML model training.
        """
        if output_file is None:
            output_file = config.TRAFFIC_CSV_PATH

        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Ensure class balance
        samples_per_class = num_samples // 4
        categories = ['NORMAL', 'PORT_SCAN', 'DOS', 'BRUTE_FORCE']
        
        data = []
        base_time = datetime.now() - timedelta(hours=24)

        for cat in categories:
            for i in range(samples_per_class):
                ts = (base_time + timedelta(seconds=i*30 + random.randint(0, 10))).strftime("%Y-%m-%d %H:%M:%S")
                record = self.generate_single_flow(attack_type=cat, timestamp=ts)
                data.append(record)

        random.shuffle(data)
        df = pd.DataFrame(data)
        df.to_csv(output_file, index=False)
        print(f"Generated synthetic training dataset with {len(df)} records at: {output_file}")
        return df


if __name__ == "__main__":
    generator = TrafficGenerator()
    generator.generate_dataset(num_samples=1600)
