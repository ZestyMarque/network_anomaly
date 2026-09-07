import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import numpy as np
import pandas as pd
from src.detection.detector import AnomalyDetector, RuleBasedDetector
from src.processing.feature_extractor import FeatureExtractor
from src.collector.packet_capture import PacketGenerator


def _make_test_features():
    data = {
        'packet_count': [100, 200, 150, 5000, 80, 120, 300, 400, 250, 6000],
        'bytes_mean': [500, 450, 600, 60, 550, 480, 420, 380, 520, 55],
        'bytes_std': [200, 180, 220, 20, 190, 210, 170, 160, 195, 15],
        'unique_src_ip': [10, 15, 12, 200, 8, 11, 14, 18, 13, 250],
        'unique_dst_port': [5, 8, 6, 100, 4, 7, 9, 10, 6, 120],
        'syn_ratio': [0.1, 0.05, 0.08, 0.95, 0.12, 0.06, 0.07, 0.09, 0.11, 0.92],
        'packets_per_sec': [20, 40, 30, 1000, 16, 24, 60, 80, 50, 1200],
        'bytes_per_sec': [10000, 18000, 18000, 60000, 8800, 11520, 25200, 30400, 26000, 66000],
        'src_entropy': [2.5, 3.0, 2.8, 5.5, 2.3, 2.7, 3.2, 3.5, 2.9, 6.0],
        'dst_port_entropy': [1.5, 2.0, 1.8, 6.0, 1.3, 1.6, 2.2, 2.5, 1.9, 6.5],
    }
    return pd.DataFrame(data)


def test_isolation_forest():
    df = _make_test_features()
    detector = AnomalyDetector(method='isolation_forest', contamination=0.2)
    detector.fit(df)
    results = detector.predict(df)
    assert 'is_anomaly' in results.columns
    assert 'anomaly_score' in results.columns
    assert results['is_anomaly'].sum() >= 1


def test_lof():
    df = _make_test_features()
    detector = AnomalyDetector(method='lof', contamination=0.2, n_neighbors=5)
    detector.fit(df)
    results = detector.predict(df)
    assert 'is_anomaly' in results.columns


def test_one_class_svm():
    df = _make_test_features()
    detector = AnomalyDetector(method='one_class_svm', nu=0.2)
    detector.fit(df)
    results = detector.predict(df)
    assert 'is_anomaly' in results.columns


def test_rule_detector():
    df = _make_test_features()
    detector = RuleBasedDetector.default_rules()
    results = detector.detect(df)
    assert 'has_alert' in results.columns
    assert 'alerts' in results.columns


def test_rule_detector_triggers():
    df = _make_test_features()
    detector = RuleBasedDetector.default_rules()
    results = detector.detect(df)
    syn_high = df['syn_ratio'] > 0.8
    assert results['has_alert'].sum() >= syn_high.sum()


def test_rule_high_syn():
    detector = RuleBasedDetector.default_rules()
    df = pd.DataFrame({'syn_ratio': [0.9, 0.1]})
    results = detector.detect(df)
    assert bool(results['has_alert'].iloc[0]) == True
    assert bool(results['has_alert'].iloc[1]) == False


def test_rule_high_packet_rate():
    detector = RuleBasedDetector.default_rules()
    df = pd.DataFrame({'packets_per_sec': [6000, 100]})
    results = detector.detect(df)
    assert bool(results['has_alert'].iloc[0]) == True
    assert bool(results['has_alert'].iloc[1]) == False


def test_save_load_model():
    df = _make_test_features()
    detector = AnomalyDetector(method='isolation_forest')
    detector.fit(df)
    detector.save_model('data/test_model.joblib')
    detector2 = AnomalyDetector(method='isolation_forest')
    detector2.load_model('data/test_model.joblib')
    r1 = detector.predict(df)['is_anomaly']
    r2 = detector2.predict(df)['is_anomaly']
    assert (r1 == r2).all()
    os.remove('data/test_model.joblib')


def test_feature_extractor_windows():
    gen = PacketGenerator()
    df = gen.generate_normal_traffic(n_packets=500)
    extractor = FeatureExtractor(window_size=1.0)
    windows = extractor.aggregate_window(df)
    assert len(windows) > 0
    for col in ['packet_count', 'bytes_mean', 'bytes_std', 'unique_src_ip',
                'packets_per_sec', 'bytes_per_sec', 'proto_tcp', 'proto_udp']:
        assert col in windows.columns


def test_feature_extractor_empty():
    extractor = FeatureExtractor()
    df = pd.DataFrame()
    result = extractor.aggregate_window(df)
    assert result.empty


def test_end_to_end_detection():
    gen = PacketGenerator()
    normal = gen.generate_normal_traffic(n_packets=500)
    traffic = pd.concat([
        normal,
        gen.generate_ddos(100, start_time=normal['timestamp'].max() + 0.1)
    ], ignore_index=True)
    traffic = traffic.sort_values('timestamp').reset_index(drop=True)
    extractor = FeatureExtractor(window_size=1.0)
    windows = extractor.aggregate_window(traffic)
    detector = AnomalyDetector(method='isolation_forest', contamination=0.2)
    detector.fit(windows)
    results = detector.predict(windows)
    assert results['is_anomaly'].sum() >= 1


if __name__ == '__main__':
    test_isolation_forest()
    test_lof()
    test_one_class_svm()
    test_rule_detector()
    test_rule_detector_triggers()
    test_rule_high_syn()
    test_rule_high_packet_rate()
    test_save_load_model()
    test_feature_extractor_windows()
    test_feature_extractor_empty()
    test_end_to_end_detection()
    print("All detector tests passed!")
