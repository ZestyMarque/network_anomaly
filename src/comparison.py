import numpy as np
import pandas as pd
from src.collector.packet_capture import PacketGenerator
from src.processing.feature_extractor import FeatureExtractor
from src.detection.detector import AnomalyDetector, RuleBasedDetector
from src.utils.helpers import print_detection_summary


def run_method_comparison(window_features, true_labels, method_configs=None):
    if method_configs is None:
        method_configs = {
            'Isolation Forest': {'method': 'isolation_forest', 'contamination': 0.15},
            'LOF': {'method': 'lof', 'contamination': 0.15, 'n_neighbors': 10},
            'One-Class SVM': {'method': 'one_class_svm', 'nu': 0.15, 'kernel': 'rbf'},
        }
    results = {}
    for name, params in method_configs.items():
        print(f"\n{'='*55}")
        print(f"  Method: {name}")
        print(f"{'='*55}")
        try:
            detector = AnomalyDetector(**params)
            detector.fit(window_features)
            preds = detector.predict(window_features)
            y_pred = preds['is_anomaly'].values
            y_scores = preds['anomaly_score'].values
            tp = ((y_pred == 1) & (true_labels == 1)).sum()
            fp = ((y_pred == 1) & (true_labels == 0)).sum()
            tn = ((y_pred == 0) & (true_labels == 0)).sum()
            fn = ((y_pred == 0) & (true_labels == 1)).sum()
            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 1e-10)
            accuracy = (tp + tn) / max(len(true_labels), 1)
            tpr = recall
            fpr = fp / max(fp + tn, 1)
            print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
            print(f"  Precision={precision:.4f}  Recall={recall:.4f}  F1={f1:.4f}")
            print(f"  Accuracy={accuracy:.4f}  TPR={tpr:.4f}  FPR={fpr:.4f}")
            results[name] = {
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'accuracy': accuracy,
                'tpr': tpr,
                'fpr': fpr,
                'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn),
                'y_pred': y_pred,
                'y_scores': y_scores,
            }
        except Exception as e:
            print(f"  ERROR: {e}")
            results[name] = {
                'precision': 0, 'recall': 0, 'f1_score': 0, 'accuracy': 0,
                'tpr': 0, 'fpr': 1, 'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0,
                'y_pred': np.zeros(len(true_labels)),
                'y_scores': np.zeros(len(true_labels)),
            }
    print(f"\n{'='*55}")
    print("  SUMMARY")
    print(f"{'='*55}")
    summary_data = []
    for name, res in results.items():
        summary_data.append({
            'Method': name,
            'Precision': f"{res['precision']:.4f}",
            'Recall': f"{res['recall']:.4f}",
            'F1': f"{res['f1_score']:.4f}",
            'Accuracy': f"{res['accuracy']:.4f}",
        })
    summary_df = pd.DataFrame(summary_data)
    print(summary_df.to_string(index=False))
    return results


def run_full_analysis(n_normal=5000, attack_configs=None, window_size=2.0):
    print("=" * 60)
    print("  NETWORK ANOMALY DETECTION - FULL ANALYSIS")
    print("=" * 60)
    print("\n[*] Generating mixed traffic...")
    gen = PacketGenerator()
    if attack_configs is None:
        attack_configs = [
            {'type': 'ddos', 'count': 300},
            {'type': 'port_scan', 'count': 200},
            {'type': 'bruteforce', 'count': 100},
            {'type': 'data_exfiltration', 'count': 150},
        ]
    traffic_df, packet_labels = gen.generate_mixed_traffic(
        n_normal=n_normal, attack_configs=attack_configs
    )
    n_anomalies = sum(1 for v in packet_labels if v == 1)
    print(f"  Total packets: {len(traffic_df)}")
    print(f"  Normal: {len(packet_labels) - n_anomalies}")
    print(f"  Anomalies: {n_anomalies}")
    attack_counts = traffic_df['attack_type'].value_counts() if 'attack_type' in traffic_df.columns else {}
    for at, cnt in attack_counts.items():
        print(f"    - {at}: {cnt}")
    print("\n[*] Extracting window features...")
    extractor = FeatureExtractor(window_size=window_size)
    window_features = extractor.aggregate_window(traffic_df)
    print(f"  Windows generated: {len(window_features)}")
    start_time = traffic_df['timestamp'].min()
    traffic_df['window_idx'] = ((traffic_df['timestamp'] - start_time) // window_size).astype(int)
    window_labels = traffic_df.groupby('window_idx')['attack_type'].apply(
        lambda x: x.notna().any()
    ).astype(int).values
    wn = len(window_features)
    window_labels = window_labels[:wn] if len(window_labels) >= wn else np.pad(
        window_labels, (0, wn - len(window_labels)), 'constant'
    )
    print(f"  Anomalous windows: {window_labels.sum()}")
    print("\n[*] Rule-based detection...")
    rule_detector = RuleBasedDetector.default_rules()
    rule_results = rule_detector.detect(window_features)
    rule_hits = rule_results['has_alert'].sum()
    print(f"  Rule alerts triggered: {rule_hits}")
    print("\n[*] Running ML methods comparison...")
    comparison_results = run_method_comparison(window_features, window_labels)
    print("\n[*] Running best method with full details...")
    best_method = max(comparison_results, key=lambda k: comparison_results[k]['f1_score'])
    print(f"  Best method: {best_method}")
    best_params = {'contamination': 0.15}
    detector = AnomalyDetector(method='isolation_forest', **best_params)
    detector.fit(window_features)
    full_results = detector.predict(window_features)
    full_results['true_label'] = window_labels
    full_results['rule_alert'] = rule_results['has_alert']
    full_results['is_alert'] = full_results['is_anomaly'] | full_results['rule_alert']
    rule_df = rule_results['alerts'].values
    full_results['rule_alerts_detail'] = rule_df
    return {
        'traffic_df': traffic_df,
        'window_features': window_features,
        'full_results': full_results,
        'comparison_results': comparison_results,
        'window_labels': window_labels,
        'packet_labels': packet_labels,
    }


if __name__ == '__main__':
    results = run_full_analysis()
