import time
import random
from collections import defaultdict
from threading import Thread, Event
from queue import Queue

import pandas as pd

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketCapture:
    def __init__(self, interface=None, max_packets=10000, timeout=60):
        self.interface = interface
        self.max_packets = max_packets
        self.timeout = timeout
        self.packet_queue = Queue()
        self._stop_event = Event()
        self._thread = None
        self.packets_buffer = []

    def _packet_handler(self, packet):
        if self._stop_event.is_set():
            return
        features = self._extract_features(packet)
        if features:
            self.packet_queue.put(features)

    def _extract_features(self, packet):
        if not packet.haslayer(IP):
            return None
        ip_layer = packet[IP]
        ts = packet.time if hasattr(packet, 'time') else time.time()
        features = {
            'timestamp': ts,
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'proto': ip_layer.proto,
            'length': len(packet),
            'ttl': ip_layer.ttl,
        }
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            features.update({
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'flags': str(tcp.flags),
                'tcp_window': tcp.window,
                'tcp_len': len(tcp),
            })
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            features.update({
                'src_port': udp.sport,
                'dst_port': udp.dport,
                'udp_len': len(udp),
            })
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            features.update({
                'icmp_type': icmp.type,
                'icmp_code': icmp.code,
            })
        return features

    def start(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Install with: pip install scapy")
        self._stop_event.clear()
        self._thread = Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def _capture_loop(self):
        sniff(
            iface=self.interface,
            prn=self._packet_handler,
            store=False,
            stop_filter=lambda p: self._stop_event.is_set(),
            timeout=self.timeout,
        )

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
        self._drain_queue()

    def _drain_queue(self):
        while not self.packet_queue.empty():
            self.packets_buffer.append(self.packet_queue.get())

    def get_packets_dataframe(self):
        self._drain_queue()
        if not self.packets_buffer:
            return pd.DataFrame()
        return pd.DataFrame(self.packets_buffer)

    def load_pcap(self, pcap_path):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed")
        from scapy.all import rdpcap
        packets = rdpcap(pcap_path)
        for packet in packets:
            features = self._extract_features(packet)
            if features:
                self.packets_buffer.append(features)
        return len(self.packets_buffer)


class PacketGenerator:
    def __init__(self, base_ip="192.168.1.100"):
        self.base_ip = base_ip
        self.counter = defaultdict(int)
        self.normal_ports = [80, 443, 53, 22, 3306, 8080, 8443]
        self.client_ips = [f"192.168.1.{i}" for i in range(2, 52)]

    def generate_normal_traffic(self, n_packets=100):
        records = []
        protocols = [6, 17, 1]
        weights = [0.7, 0.25, 0.05]
        for i in range(n_packets):
            ts = time.time() + i * random.uniform(0.005, 0.05)
            src_port = random.randint(30000, 60000)
            dst_port = random.choice(self.normal_ports)
            proto = random.choices(protocols, weights=weights, k=1)[0]
            pkt_len = int(random.gauss(400, 200))
            pkt_len = max(40, min(1500, pkt_len))
            features = {
                'timestamp': round(ts, 6),
                'src_ip': random.choice(self.client_ips),
                'dst_ip': self.base_ip,
                'proto': proto,
                'length': pkt_len,
                'ttl': random.randint(64, 128),
                'src_port': src_port,
                'dst_port': dst_port,
            }
            if proto == 6:
                flags_pool = ['A', 'PA', 'A', 'S', 'SA', 'A', 'FA']
                features['flags'] = random.choice(flags_pool)
                features['tcp_window'] = random.randint(8192, 65535)
            records.append(features)
        return pd.DataFrame(records)

    def generate_ddos(self, n_packets, start_time=None):
        if start_time is None:
            start_time = time.time()
        records = []
        for i in range(n_packets):
            ts = start_time + i * 0.0005
            records.append({
                'timestamp': ts,
                'src_ip': f"10.0.0.{random.randint(0, 254)}",
                'dst_ip': self.base_ip,
                'proto': 6,
                'length': random.randint(40, 80),
                'ttl': random.randint(64, 128),
                'src_port': random.randint(10000, 65535),
                'dst_port': 80,
                'flags': 'S',
                'tcp_window': random.randint(1024, 8192),
            })
        return pd.DataFrame(records)

    def generate_port_scan(self, n_packets, start_time=None):
        if start_time is None:
            start_time = time.time()
        records = []
        src_ip = f"10.0.0.99"
        for i in range(n_packets):
            ts = start_time + i * 0.0003
            port = random.randint(1, 1024) if i % 2 == 0 else random.randint(1025, 65535)
            records.append({
                'timestamp': ts,
                'src_ip': src_ip if i % 3 != 0 else f"10.0.0.{random.randint(100, 200)}",
                'dst_ip': self.base_ip,
                'proto': 6,
                'length': 60,
                'ttl': 64,
                'src_port': random.randint(40000, 50000),
                'dst_port': port,
                'flags': 'S',
                'tcp_window': 1024,
            })
        return pd.DataFrame(records)

    def generate_bruteforce(self, n_packets, start_time=None):
        if start_time is None:
            start_time = time.time()
        records = []
        src_ip = "10.0.0.88"
        for i in range(n_packets):
            ts = start_time + i * 0.02
            records.append({
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': self.base_ip,
                'proto': 6,
                'length': random.randint(100, 300),
                'ttl': 128,
                'src_port': random.randint(40000, 50000),
                'dst_port': 22,
                'flags': random.choice(['PA', 'A', 'FA', 'R']),
                'tcp_window': random.randint(4096, 16384),
            })
        return pd.DataFrame(records)

    def generate_data_exfiltration(self, n_packets, start_time=None):
        if start_time is None:
            start_time = time.time()
        records = []
        src_ip = "192.168.1.50"
        for i in range(n_packets):
            ts = start_time + i * random.uniform(0.001, 0.005)
            pkt_len = int(random.gauss(1200, 200))
            pkt_len = max(800, min(1500, pkt_len))
            records.append({
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': f"203.0.113.{random.randint(1, 10)}",
                'proto': 6,
                'length': pkt_len,
                'ttl': random.randint(64, 128),
                'src_port': random.randint(30000, 60000),
                'dst_port': 443,
                'flags': random.choice(['PA', 'A', 'PA', 'A', 'FA']),
                'tcp_window': random.randint(16384, 65535),
            })
        return pd.DataFrame(records)

    def generate_mixed_traffic(self, n_normal=3000, attack_configs=None):
        if attack_configs is None:
            attack_configs = [
                {'type': 'ddos', 'count': 300},
                {'type': 'port_scan', 'count': 200},
                {'type': 'bruteforce', 'count': 100},
                {'type': 'data_exfiltration', 'count': 150},
            ]
        normal_df = self.generate_normal_traffic(n_packets=n_normal)
        last_ts = normal_df['timestamp'].max()
        traffic_parts = [normal_df]
        attack_generators = {
            'ddos': self.generate_ddos,
            'port_scan': self.generate_port_scan,
            'bruteforce': self.generate_bruteforce,
            'data_exfiltration': self.generate_data_exfiltration,
        }
        anomaly_labels = []
        for cfg in attack_configs:
            gen = attack_generators.get(cfg['type'])
            if gen:
                attack_df = gen(cfg['count'], start_time=last_ts + random.uniform(0.1, 0.5))
                attack_df['attack_type'] = cfg['type']
                traffic_parts.append(attack_df)
                anomaly_labels.extend([1] * len(attack_df))
                last_ts = attack_df['timestamp'].max()
        anomaly_labels.extend([0] * len(normal_df))
        df = pd.concat(traffic_parts, ignore_index=True)
        df = df.sort_values('timestamp').reset_index(drop=True)
        return df, anomaly_labels
