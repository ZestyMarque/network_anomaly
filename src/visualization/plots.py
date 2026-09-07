import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, auc, precision_recall_curve


PLOT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), 'data', 'plots')


def _ensure_plot_dir():
    os.makedirs(PLOT_DIR, exist_ok=True)
    return PLOT_DIR


def plot_time_series_anomalies(window_features, anomaly_results, save=True):
    plot_dir = _ensure_plot_dir()
    fig, axes = plt.subplots(4, 1, figsize=(14, 10), sharex=True)
    metrics = [
        ('packet_count', 'Packet Count', 'Packets'),
        ('bytes_mean', 'Mean Packet Size', 'Bytes'),
        ('syn_ratio', 'SYN Ratio', 'Ratio'),
        ('unique_dst_port', 'Unique Dest Ports', 'Count'),
    ]
    is_anomaly = anomaly_results['is_anomaly'].values if 'is_anomaly' in anomaly_results else None
    anomaly_windows = window_features.index[is_anomaly].values if is_anomaly is not None else []
    for ax, (col, title, ylabel) in zip(axes, metrics):
        if col in window_features.columns:
            ax.plot(window_features.index, window_features[col].values,
                    color='steelblue', linewidth=1.5, alpha=0.8)
            if len(anomaly_windows) > 0:
                anom_vals = window_features.loc[anomaly_windows, col].values
                ax.scatter(anomaly_windows, anom_vals,
                          color='red', s=40, zorder=5, label='Anomaly', marker='x')
            ax.set_ylabel(ylabel, fontsize=10)
            ax.set_title(title, fontsize=11, fontweight='bold')
            ax.legend(loc='upper right', fontsize=8)
            ax.grid(True, alpha=0.3)
    axes[-1].set_xlabel('Window Index', fontsize=10)
    plt.tight_layout()
    if save:
        path = os.path.join(plot_dir, 'time_series_anomalies.png')
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"[*] Saved: {path}")
    plt.close(fig)
    return fig


def plot_confusion_matrix(y_true, y_pred, save=True):
    plot_dir = _ensure_plot_dir()
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=True,
                xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'],
                ax=ax)
    ax.set_xlabel('Predicted', fontsize=11)
    ax.set_ylabel('Actual', fontsize=11)
    ax.set_title('Confusion Matrix', fontsize=13, fontweight='bold')
    plt.tight_layout()
    if save:
        path = os.path.join(plot_dir, 'confusion_matrix.png')
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"[*] Saved: {path}")
    plt.close(fig)
    return fig


def plot_anomaly_score_distribution(results, save=True):
    plot_dir = _ensure_plot_dir()
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    if 'anomaly_score' in results.columns:
        scores = results['anomaly_score'].values
        is_anom = results['is_anomaly'].values if 'is_anomaly' in results.columns else None
        ax = axes[0]
        ax.hist(scores, bins=20, color='steelblue', edgecolor='white', alpha=0.7)
        if is_anom is not None:
            ax.hist(scores[is_anom], bins=15, color='red', alpha=0.6, label='Anomalies')
        ax.set_xlabel('Anomaly Score', fontsize=10)
        ax.set_ylabel('Frequency', fontsize=10)
        ax.set_title('Anomaly Score Distribution', fontsize=11, fontweight='bold')
        ax.legend(fontsize=8)
        ax.grid(True, alpha=0.3)
        ax = axes[1]
        if is_anom is not None:
            colors = ['red' if a else 'steelblue' for a in is_anom]
            ax.scatter(range(len(scores)), scores, c=colors, alpha=0.7, s=30)
            ax.axhline(y=0, color='gray', linestyle='--', alpha=0.5)
        ax.set_xlabel('Window Index', fontsize=10)
        ax.set_ylabel('Anomaly Score', fontsize=10)
        ax.set_title('Anomaly Scores by Window', fontsize=11, fontweight='bold')
        ax.grid(True, alpha=0.3)
    plt.tight_layout()
    if save:
        path = os.path.join(plot_dir, 'anomaly_score_distribution.png')
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"[*] Saved: {path}")
    plt.close(fig)
    return fig


def plot_feature_correlation(features_df, save=True):
    plot_dir = _ensure_plot_dir()
    numeric_cols = features_df.select_dtypes(include=[np.number]).columns.tolist()
    if len(numeric_cols) > 15:
        numeric_cols = numeric_cols[:15]
    corr = features_df[numeric_cols].corr()
    fig, ax = plt.subplots(figsize=(10, 8))
    mask = np.triu(np.ones_like(corr, dtype=bool))
    sns.heatmap(corr, mask=mask, annot=True, fmt='.2f', cmap='RdBu_r',
                center=0, square=True, cbar_kws={'shrink': 0.8}, ax=ax)
    ax.set_title('Feature Correlation Matrix', fontsize=13, fontweight='bold')
    plt.tight_layout()
    if save:
        path = os.path.join(plot_dir, 'feature_correlation.png')
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"[*] Saved: {path}")
    plt.close(fig)
    return fig


def plot_roc_curve(y_true, y_scores, save=True):
    plot_dir = _ensure_plot_dir()
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC (AUC = {roc_auc:.3f})')
    ax.plot([0, 1], [0, 1], color='gray', linestyle='--', alpha=0.5)
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('False Positive Rate', fontsize=11)
    ax.set_ylabel('True Positive Rate', fontsize=11)
    ax.set_title('Receiver Operating Characteristic', fontsize=13, fontweight='bold')
    ax.legend(loc='lower right', fontsize=10)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    if save:
        path = os.path.join(plot_dir, 'roc_curve.png')
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"[*] Saved: {path}")
    plt.close(fig)
    return fig, roc_auc


def plot_precision_recall_curve(y_true, y_scores, save=True):
    plot_dir = _ensure_plot_dir()
    precision, recall, _ = precision_recall_curve(y_true, y_scores)
    pr_auc = auc(recall, precision)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot(recall, precision, color='green', lw=2, label=f'PR (AUC = {pr_auc:.3f})')
    ax.set_xlabel('Recall', fontsize=11)
    ax.set_ylabel('Precision', fontsize=11)
    ax.set_title('Precision-Recall Curve', fontsize=13, fontweight='bold')
    ax.legend(loc='lower left', fontsize=10)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    if save:
        path = os.path.join(plot_dir, 'precision_recall_curve.png')
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"[*] Saved: {path}")
    plt.close(fig)
    return fig, pr_auc


def plot_method_comparison(comparison_results, save=True):
    plot_dir = _ensure_plot_dir()
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    methods = list(comparison_results.keys())
    metrics = ['precision', 'recall', 'f1_score']
    titles = ['Precision', 'Recall', 'F1-Score']
    colors = sns.color_palette('Set2', n_colors=len(methods))
    x = np.arange(len(methods))
    width = 0.25
    for i, (metric, title) in enumerate(zip(metrics, titles)):
        ax = axes[i]
        values = [comparison_results[m].get(metric, 0) for m in methods]
        bars = ax.bar(x, values, width, color=colors, edgecolor='gray', linewidth=0.5)
        for bar, v in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f'{v:.3f}', ha='center', va='bottom', fontsize=9)
        ax.set_xticks(x)
        ax.set_xticklabels(methods, rotation=15, fontsize=9)
        ax.set_ylabel(title, fontsize=10)
        ax.set_title(title, fontsize=11, fontweight='bold')
        ax.set_ylim(0, 1.15)
        ax.grid(True, alpha=0.3, axis='y')
    plt.suptitle('Algorithm Comparison', fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()
    if save:
        path = os.path.join(plot_dir, 'method_comparison.png')
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"[*] Saved: {path}")
    plt.close(fig)
    return fig


def plot_window_features_heatmap(window_features, anomaly_results, save=True):
    plot_dir = _ensure_plot_dir()
    plot_cols = ['packet_count', 'bytes_mean', 'bytes_std', 'syn_ratio',
                 'unique_src_ip', 'unique_dst_port', 'packets_per_sec',
                 'src_entropy', 'dst_port_entropy']
    available = [c for c in plot_cols if c in window_features.columns]
    if len(available) < 3:
        return None
    data = window_features[available].copy()
    data = (data - data.mean()) / data.std().replace(0, 1)
    fig, ax = plt.subplots(figsize=(12, 6))
    im = ax.imshow(data.T, aspect='auto', cmap='RdBu_r', interpolation='nearest')
    ax.set_yticks(range(len(available)))
    ax.set_yticklabels(available, fontsize=9)
    ax.set_xlabel('Window Index', fontsize=10)
    ax.set_title('Normalized Window Features (z-scores)', fontsize=13, fontweight='bold')
    cbar = plt.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label('Z-Score', fontsize=9)
    if 'is_anomaly' in anomaly_results.columns:
        anom_idx = [i for i, v in enumerate(anomaly_results['is_anomaly'].values) if v]
        for idx in anom_idx:
            ax.axvline(x=idx, color='red', alpha=0.3, linewidth=1)
    plt.tight_layout()
    if save:
        path = os.path.join(plot_dir, 'features_heatmap.png')
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"[*] Saved: {path}")
    plt.close(fig)
    return fig


def generate_all_plots(window_features, anomaly_results, y_true=None, y_score=None,
                       comparison_results=None):
    print("[*] Generating all visualizations...")
    plot_time_series_anomalies(window_features, anomaly_results)
    plot_anomaly_score_distribution(anomaly_results)
    plot_feature_correlation(window_features)
    plot_window_features_heatmap(window_features, anomaly_results)
    if y_true is not None and y_score is not None:
        plot_roc_curve(y_true, y_score)
        plot_precision_recall_curve(y_true, y_score)
    if y_true is not None and 'is_anomaly' in anomaly_results.columns:
        plot_confusion_matrix(y_true, anomaly_results['is_anomaly'].values)
    if comparison_results:
        plot_method_comparison(comparison_results)
    print(f"[*] All plots saved to: {PLOT_DIR}")
