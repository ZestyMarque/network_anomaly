import json
import csv
import os
import pandas as pd


def save_results(df, path, format='csv'):
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
    if format == 'csv':
        df.to_csv(path, index=False)
    elif format == 'json':
        df.to_json(path, orient='records', date_format='iso')
    elif format == 'parquet':
        df.to_parquet(path, index=False)


def load_data(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == '.csv':
        return pd.read_csv(path)
    elif ext == '.json':
        return pd.read_json(path)
    elif ext == '.parquet':
        return pd.read_parquet(path)
    else:
        raise ValueError(f"Unsupported format: {ext}")


def print_detection_summary(df):
    if 'is_anomaly' not in df.columns:
        print("No anomaly detection results found.")
        return
    n_total = len(df)
    n_anomalies = df['is_anomaly'].sum()
    print(f"{'='*50}")
    print(f"Total windows analyzed: {n_total}")
    print(f"Anomalies detected:     {n_anomalies} ({n_anomalies/max(n_total,1)*100:.1f}%)")
    print(f"Normal windows:         {n_total - n_anomalies}")
    if 'anomaly_score' in df.columns and n_anomalies > 0:
        print(f"\nAnomaly score range: {df['anomaly_score'].min():.4f} - {df['anomaly_score'].max():.4f}")
        anomaly_scores = df[df['is_anomaly']]['anomaly_score']
        print(f"Mean anomaly score: {anomaly_scores.mean():.4f}")
    print(f"{'='*50}")
