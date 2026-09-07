import pandas as pd
import numpy as np


class FeatureExtractor:
    def __init__(self, window_size=5.0):
        self.window_size = window_size

    def aggregate_window(self, df):
        if df.empty:
            return pd.DataFrame()
        df = df.copy()
        df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
        df = df.sort_values('timestamp')
        start_time = df['timestamp'].min()
        df['window'] = ((df['timestamp'] - start_time) // self.window_size).astype(int)
        agg_features = []
        for win, group in df.groupby('window'):
            features = {'window': win, 'window_start': start_time + win * self.window_size}
            features['packet_count'] = len(group)
            features['bytes_total'] = group['length'].sum()
            features['bytes_mean'] = group['length'].mean()
            features['bytes_std'] = group['length'].std() if len(group) > 1 else 0.0
            features['bytes_min'] = group['length'].min()
            features['bytes_max'] = group['length'].max()
            features['ttl_mean'] = group['ttl'].mean()
            features['ttl_std'] = group['ttl'].std() if len(group) > 1 else 0.0
            if 'flags' in group.columns:
                syn_count = group['flags'].str.contains('S', na=False).sum()
                features['syn_count'] = syn_count
                features['syn_ratio'] = syn_count / max(len(group), 1)
            features['unique_src_ip'] = group['src_ip'].nunique()
            features['unique_dst_ip'] = group['dst_ip'].nunique()
            features['unique_dst_port'] = group['dst_port'].nunique() if 'dst_port' in group.columns else 0
            features['unique_src_port'] = group['src_port'].nunique() if 'src_port' in group.columns else 0
            features['proto_tcp'] = (group['proto'] == 6).sum()
            features['proto_udp'] = (group['proto'] == 17).sum()
            features['proto_icmp'] = (group['proto'] == 1).sum()
            features['packets_per_sec'] = features['packet_count'] / self.window_size
            features['bytes_per_sec'] = features['bytes_total'] / self.window_size
            features['src_entropy'] = self._entropy(group['src_ip'])
            features['dst_port_entropy'] = self._entropy(group['dst_port']) if 'dst_port' in group.columns else 0
            agg_features.append(features)
        return pd.DataFrame(agg_features)

    def _entropy(self, series):
        counts = series.value_counts()
        probs = counts / counts.sum()
        return -np.sum(probs * np.log2(probs + 1e-10))

    def extract_packet_features(self, row):
        features = {}
        features['packet_length'] = row.get('length', 0)
        features['ttl'] = row.get('ttl', 0)
        features['proto'] = row.get('proto', 0)
        features['is_tcp'] = 1 if row.get('proto') == 6 else 0
        features['is_udp'] = 1 if row.get('proto') == 17 else 0
        features['is_icmp'] = 1 if row.get('proto') == 1 else 0
        if 'src_port' in row:
            features['src_port'] = row['src_port']
            features['dst_port'] = row['dst_port']
            features['is_well_known_dst'] = 1 if row.get('dst_port', 0) < 1024 else 0
        if 'flags' in row:
            features['is_syn'] = 1 if 'S' in str(row['flags']) else 0
            features['is_ack'] = 1 if 'A' in str(row['flags']) else 0
            features['is_fin'] = 1 if 'F' in str(row['flags']) else 0
            features['is_rst'] = 1 if 'R' in str(row['flags']) else 0
        return features
