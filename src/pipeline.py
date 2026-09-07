import time
import pandas as pd
from src.collector.packet_capture import PacketCapture, PacketGenerator
from src.processing.feature_extractor import FeatureExtractor
from src.detection.detector import AnomalyDetector, RuleBasedDetector
from src.utils.helpers import save_results, print_detection_summary


class DetectionPipeline:
    def __init__(self, window_size=5.0):
        self.collector = None
        self.feature_extractor = FeatureExtractor(window_size=window_size)
        self.ml_detector = None
        self.rule_detector = RuleBasedDetector.default_rules()
        self.results = []

    def run_offline(self, df_packets, method='isolation_forest', **kwargs):
        print("[*] Extracting window features...")
        window_features = self.feature_extractor.aggregate_window(df_packets)
        if window_features.empty:
            print("[!] No features extracted.")
            return pd.DataFrame()
        print(f"[*] Generated {len(window_features)} windows.")
        print("[*] Initializing anomaly detector...")
        self.ml_detector = AnomalyDetector(method=method, **kwargs)
        print("[*] Training model...")
        self.ml_detector.fit(window_features)
        print("[*] Running detection...")
        ml_results = self.ml_detector.predict(window_features)
        print("[*] Running rule-based detection...")
        rule_results = self.rule_detector.detect(window_features)
        combined = ml_results.copy()
        combined['rule_alert'] = rule_results['has_alert']
        combined['rule_alerts_detail'] = rule_results['alerts']
        combined['is_alert'] = combined['is_anomaly'] | combined['rule_alert']
        self.results = combined
        return combined

    def run_offline_with_labels(self, df_packets, packet_labels=None, method='isolation_forest', **kwargs):
        results = self.run_offline(df_packets, method=method, **kwargs)
        if packet_labels is not None and not results.empty:
            df = df_packets.copy()
            df['label'] = packet_labels
            start_time = df['timestamp'].min()
            window_size = self.feature_extractor.window_size
            df['window_idx'] = ((df['timestamp'] - start_time) // window_size).astype(int)
            window_labels = df.groupby('window_idx')['label'].max()
            matched_labels = []
            for _, row in results.iterrows():
                win = int(row['window'])
                matched_labels.append(window_labels.get(win, 0))
            results['true_label'] = matched_labels
            tp = ((results['is_anomaly']) & (results['true_label'] == 1)).sum()
            fp = ((results['is_anomaly']) & (results['true_label'] == 0)).sum()
            tn = ((~results['is_anomaly']) & (results['true_label'] == 0)).sum()
            fn = ((~results['is_anomaly']) & (results['true_label'] == 1)).sum()
            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 1e-10)
            print(f"\n{'='*50}")
            print("CLASSIFICATION REPORT")
            print(f"{'='*50}")
            print(f"True Positives:  {tp}")
            print(f"False Positives: {fp}")
            print(f"True Negatives:  {tn}")
            print(f"False Negatives: {fn}")
            print(f"Precision: {precision:.4f}")
            print(f"Recall:    {recall:.4f}")
            print(f"F1-Score:  {f1:.4f}")
            print(f"{'='*50}")
            results['precision'] = precision
            results['recall'] = recall
            results['f1_score'] = f1
        return results


def demo():
    print("[*] Generating synthetic network traffic...")
    gen = PacketGenerator()
    normal = gen.generate_normal_traffic(n_packets=2000)
    traffic = gen.generate_anomaly_traffic(normal, anomaly_type='ddos', ratio=0.15)
    true_labels = (traffic['src_ip'].str.startswith('10.0.0')).astype(int)
    print(f"[*] Generated {len(traffic)} packets ({true_labels.sum()} anomalous)")
    pipeline = DetectionPipeline(window_size=2.0)
    results = pipeline.run_offline_with_labels(
        traffic,
        packet_labels=true_labels.values,
        method='isolation_forest',
        contamination=0.15,
    )
    print_detection_summary(results)
    save_results(results, 'data/results_demo.csv')
    print("[*] Results saved to data/results_demo.csv")
    return results


if __name__ == '__main__':
    demo()
