import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib
import os


class AnomalyDetector:
    def __init__(self, method='isolation_forest', **kwargs):
        self.method = method
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.threshold = kwargs.get('threshold', 0.5)

        if method == 'isolation_forest':
            self.model = IsolationForest(
                n_estimators=kwargs.get('n_estimators', 100),
                contamination=kwargs.get('contamination', 'auto'),
                random_state=42,
            )
        elif method == 'lof':
            self.model = LocalOutlierFactor(
                n_neighbors=kwargs.get('n_neighbors', 20),
                contamination=kwargs.get('contamination', 'auto'),
                novelty=True,
            )
        elif method == 'one_class_svm':
            self.model = OneClassSVM(
                kernel=kwargs.get('kernel', 'rbf'),
                gamma=kwargs.get('gamma', 'auto'),
                nu=kwargs.get('nu', 0.1),
            )
        else:
            raise ValueError(f"Unknown method: {method}")

    def _validate_features(self, df):
        required = ['packet_count', 'bytes_mean', 'bytes_std',
                     'unique_src_ip', 'unique_dst_port', 'syn_ratio']
        missing = [c for c in required if c not in df.columns]
        if missing:
            raise ValueError(f"Missing required features: {missing}")
        return True

    def fit(self, df, feature_cols=None):
        if feature_cols is None:
            feature_cols = ['packet_count', 'bytes_mean', 'bytes_std',
                            'unique_src_ip', 'unique_dst_port', 'syn_ratio',
                            'packets_per_sec', 'bytes_per_sec',
                            'src_entropy', 'dst_port_entropy']
        present_cols = [c for c in feature_cols if c in df.columns]
        if len(present_cols) < 3:
            raise ValueError("Need at least 3 feature columns for training")
        X = df[present_cols].fillna(0).values
        X_scaled = self.scaler.fit_transform(X)
        if self.method == 'lof':
            self.model.fit(X_scaled)
        else:
            self.model.fit(X_scaled)
        self.is_fitted = True
        self.feature_cols_ = present_cols
        return self

    def predict(self, df):
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted. Call fit() first.")
        X = df[self.feature_cols_].fillna(0).values
        X_scaled = self.scaler.transform(X)
        preds = self.model.predict(X_scaled)
        if self.method == 'isolation_forest':
            scores = self.model.decision_function(X_scaled)
            anomalies = preds == -1
        elif self.method == 'lof':
            scores = self.model.decision_function(X_scaled)
            anomalies = preds == -1
        elif self.method == 'one_class_svm':
            scores = self.model.score_samples(X_scaled)
            anomalies = preds == -1
        df_result = df.copy()
        df_result['anomaly_score'] = scores
        df_result['is_anomaly'] = anomalies
        return df_result

    def detect_streaming(self, window_df, history_df=None):
        if history_df is not None and not history_df.empty and not self.is_fitted:
            self.fit(history_df)
        if not self.is_fitted:
            result = window_df.copy()
            result['anomaly_score'] = 0.0
            result['is_anomaly'] = False
            return result
        return self.predict(window_df)

    def save_model(self, path):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_cols_': self.feature_cols_,
            'method': self.method,
            'is_fitted': self.is_fitted,
        }, path)

    def load_model(self, path):
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_cols_ = data['feature_cols_']
        self.method = data['method']
        self.is_fitted = data['is_fitted']
        return self


class RuleBasedDetector:
    def __init__(self):
        self.rules = []

    def add_rule(self, name, condition, severity='medium'):
        self.rules.append({
            'name': name,
            'condition': condition,
            'severity': severity,
        })

    def detect(self, df):
        results = []
        for _, row in df.iterrows():
            triggered = []
            for rule in self.rules:
                try:
                    if rule['condition'](row):
                        triggered.append({
                            'rule': rule['name'],
                            'severity': rule['severity'],
                        })
                except Exception:
                    pass
            results.append(triggered)
        df_result = df.copy()
        df_result['alerts'] = results
        df_result['has_alert'] = [len(r) > 0 for r in results]
        return df_result

    @staticmethod
    def default_rules():
        detector = RuleBasedDetector()
        detector.add_rule(
            'high_syn_ratio',
            lambda r: r.get('syn_ratio', 0) > 0.8,
            severity='high',
        )
        detector.add_rule(
            'high_packet_rate',
            lambda r: r.get('packets_per_sec', 0) > 5000,
            severity='high',
        )
        detector.add_rule(
            'high_port_entropy',
            lambda r: r.get('dst_port_entropy', 0) > 5.0,
            severity='medium',
        )
        detector.add_rule(
            'many_unique_ports',
            lambda r: r.get('unique_dst_port', 0) > 50,
            severity='high',
        )
        detector.add_rule(
            'low_packet_rate_high_bytes',
            lambda r: r.get('packets_per_sec', 0) < 10 and r.get('bytes_per_sec', 0) > 1_000_000,
            severity='medium',
        )
        return detector
