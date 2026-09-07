#!/usr/bin/env python3
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.pipeline import DetectionPipeline, demo
from src.collector.packet_capture import PacketCapture, PacketGenerator
from src.utils.helpers import load_data, print_detection_summary


def main():
    parser = argparse.ArgumentParser(description='Network Anomaly Detection Platform')
    parser.add_argument('--demo', action='store_true', help='Run demo with synthetic data')
    parser.add_argument('--pcap', type=str, help='Path to PCAP file for analysis')
    parser.add_argument('--live', action='store_true', help='Live capture mode')
    parser.add_argument('--interface', type=str, default=None, help='Network interface for live capture')
    parser.add_argument('--method', type=str, default='isolation_forest',
                        choices=['isolation_forest', 'lof', 'one_class_svm'],
                        help='Detection method')
    parser.add_argument('--window', type=float, default=5.0, help='Time window in seconds')
    parser.add_argument('--output', type=str, default='data/results.csv', help='Output path')
    args = parser.parse_args()

    if args.demo:
        demo()
        return

    pipeline = DetectionPipeline(window_size=args.window)

    if args.pcap:
        print(f"[*] Loading PCAP: {args.pcap}")
        collector = PacketCapture()
        n_packets = collector.load_pcap(args.pcap)
        print(f"[*] Loaded {n_packets} packets")
        packets_df = collector.get_packets_dataframe()
    elif args.live:
        print(f"[*] Starting live capture on {args.interface or 'default'} interface")
        collector = PacketCapture(interface=args.interface)
        collector.start()
        try:
            import time as t
            t.sleep(30)
        except KeyboardInterrupt:
            pass
        collector.stop()
        packets_df = collector.get_packets_dataframe()
        print(f"[*] Captured {len(packets_df)} packets")
    else:
        print("[*] Generating synthetic data for demonstration")
        gen = PacketGenerator()
        normal = gen.generate_normal_traffic(n_packets=1000)
        traffic = gen.generate_anomaly_traffic(normal, anomaly_type='ddos', ratio=0.1)
        packets_df = traffic

    results = pipeline.run_offline(packets_df, method=args.method)
    if results.empty:
        print("[!] No results generated.")
        return
    print_detection_summary(results)
    from src.utils.helpers import save_results
    save_results(results, args.output)
    print(f"[*] Results saved to {args.output}")


if __name__ == '__main__':
    main()
