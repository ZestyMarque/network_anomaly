#!/usr/bin/env python3
"""
Complete run script for the Network Anomaly Detection Platform.
Generates synthetic data, runs all detection methods, creates visualizations.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import pandas as pd
from src.collector.packet_capture import PacketGenerator
from src.processing.feature_extractor import FeatureExtractor
from src.detection.detector import AnomalyDetector, RuleBasedDetector
from src.comparison import run_method_comparison
from src.visualization.plots import generate_all_plots
from src.utils.helpers import print_detection_summary


def main():
    print("=" * 60)
    print("  NETWORK ANOMALY DETECTION PLATFORM")
    print("  Full Analysis Pipeline")
    print("=" * 60)

    print("\n[1] Generating synthetic network traffic...")
    gen = PacketGenerator()
    attack_configs = [
        {'type': 'ddos', 'count': 300},
        {'type': 'port_scan', 'count': 200},
        {'type': 'bruteforce', 'count': 100},
        {'type': 'data_exfiltration', 'count': 150},
    ]
    traffic_df, packet_labels = gen.generate_mixed_traffic(
        n_normal=5000, attack_configs=attack_configs
    )
    n_anomalies = sum(packet_labels)
    print(f"  Total packets: {len(traffic_df)}")
    print(f"  Normal packets: {len(packet_labels) - n_anomalies}")
    print(f"  Anomalous packets: {n_anomalies}")

    print("\n[2] Extracting features (window-based aggregation)...")
    WINDOW_SIZE = 2.0
    extractor = FeatureExtractor(window_size=WINDOW_SIZE)
    window_features = extractor.aggregate_window(traffic_df)
    print(f"  Time windows: {len(window_features)}")
    print(f"  Features per window: {len(window_features.columns)}")

    print("\n[3] Preparing ground truth labels...")
    start_time = traffic_df['timestamp'].min()
    traffic_df['window_idx'] = ((traffic_df['timestamp'] - start_time) // WINDOW_SIZE).astype(int)
    if 'attack_type' in traffic_df.columns:
        window_labels = traffic_df.groupby('window_idx')['attack_type'].apply(
            lambda x: x.notna().any()
        ).astype(int).values
    else:
        window_labels = np.zeros(len(window_features))
    wn = len(window_features)
    window_labels = window_labels[:wn] if len(window_labels) >= wn else np.pad(
        window_labels, (0, wn - len(window_labels)), 'constant'
    )
    print(f"  Anomalous windows: {window_labels.sum()} / {wn}")

    print("\n[4] Rule-based detection...")
    rule_detector = RuleBasedDetector.default_rules()
    rule_results = rule_detector.detect(window_features)
    print(f"  Rule alerts triggered: {rule_results['has_alert'].sum()}")

    print("\n[5] Comparing ML detection methods...")
    comparison_results = run_method_comparison(window_features, window_labels)

    print("\n[6] Running best method (Isolation Forest) with full results...")
    detector = AnomalyDetector(method='isolation_forest', contamination=0.15)
    detector.fit(window_features)
    full_results = detector.predict(window_features)
    full_results['true_label'] = window_labels
    full_results['rule_alert'] = rule_results['has_alert']
    full_results['rule_alerts_detail'] = rule_results['alerts']
    full_results['is_alert'] = full_results['is_anomaly'] | full_results['rule_alert']
    print_detection_summary(full_results)

    print("\n[7] Generating visualizations...")
    y_true = window_labels
    y_score = full_results['anomaly_score'].values
    generate_all_plots(
        window_features, full_results,
        y_true=y_true, y_score=y_score,
        comparison_results=comparison_results,
    )

    print("\n[8] Saving results...")
    os.makedirs('data', exist_ok=True)
    full_results.to_csv('data/full_results.csv', index=False)
    window_features.to_csv('data/window_features.csv', index=False)
    traffic_df.to_csv('data/traffic_data.csv', index=False)
    print("  data/full_results.csv")
    print("  data/window_features.csv")
    print("  data/traffic_data.csv")

    print("\n[9] Saving trained model...")
    detector.save_model('data/model_isolation_forest.joblib')
    print("  data/model_isolation_forest.joblib")

    print("\n" + "=" * 60)
    print("  ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"\n  Results summary:")
    print(f"  - Windows analyzed: {len(full_results)}")
    print(f"  - ML anomalies: {full_results['is_anomaly'].sum()}")
    print(f"  - Rule alerts: {full_results['rule_alert'].sum()}")
    print(f"  - Combined alerts: {full_results['is_alert'].sum()}")
    print(f"\n  Best method: {max(comparison_results, key=lambda k: comparison_results[k]['f1_score'])}")
    print(f"\n  Plots saved to: data/plots/")
    print("=" * 60)

    return {
        'window_features': window_features,
        'full_results': full_results,
        'comparison_results': comparison_results,
        'traffic_df': traffic_df,
    }


if __name__ == '__main__':
    results = main()
