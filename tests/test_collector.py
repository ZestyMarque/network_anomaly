import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pandas as pd
from src.collector.packet_capture import PacketGenerator


def test_generate_normal():
    gen = PacketGenerator()
    df = gen.generate_normal_traffic(n_packets=100)
    assert len(df) == 100
    for col in ['src_ip', 'dst_ip', 'proto', 'length', 'ttl', 'src_port', 'dst_port']:
        assert col in df.columns


def test_generate_normal_protocol_distribution():
    gen = PacketGenerator()
    df = gen.generate_normal_traffic(n_packets=1000)
    assert 600 <= (df['proto'] == 6).sum() <= 800
    assert (df['proto'] == 17).sum() > 0


def test_generate_ddos():
    gen = PacketGenerator()
    df = gen.generate_ddos(300)
    assert len(df) == 300
    assert (df['src_ip'].str.startswith('10.0.0')).all()
    assert (df['dst_port'] == 80).all()
    assert (df['flags'] == 'S').all()


def test_generate_port_scan():
    gen = PacketGenerator()
    df = gen.generate_port_scan(200)
    assert len(df) == 200
    assert (df['dst_port'] >= 1).all()
    assert (df['length'] == 60).all()


def test_generate_bruteforce():
    gen = PacketGenerator()
    df = gen.generate_bruteforce(100)
    assert len(df) == 100
    assert (df['dst_port'] == 22).all()
    assert (df['src_ip'] == '10.0.0.88').all()


def test_generate_data_exfiltration():
    gen = PacketGenerator()
    df = gen.generate_data_exfiltration(150)
    assert len(df) == 150
    assert (df['dst_port'] == 443).all()
    assert (df['src_ip'] == '192.168.1.50').all()
    assert df['length'].mean() > 800


def test_generate_mixed_traffic():
    gen = PacketGenerator()
    attack_configs = [
        {'type': 'ddos', 'count': 200},
        {'type': 'port_scan', 'count': 100},
    ]
    df, labels = gen.generate_mixed_traffic(n_normal=1000, attack_configs=attack_configs)
    assert len(df) == 1300
    assert len(labels) == 1300
    assert sum(labels) == 300
    assert 'attack_type' in df.columns
    assert df['attack_type'].notna().sum() == 300


def test_generate_mixed_traffic_ordering():
    gen = PacketGenerator()
    df, _ = gen.generate_mixed_traffic(n_normal=500, attack_configs=[{'type': 'ddos', 'count': 100}])
    assert (df['timestamp'].diff().dropna() >= 0).all()


if __name__ == '__main__':
    test_generate_normal()
    test_generate_normal_protocol_distribution()
    test_generate_ddos()
    test_generate_port_scan()
    test_generate_bruteforce()
    test_generate_data_exfiltration()
    test_generate_mixed_traffic()
    test_generate_mixed_traffic_ordering()
    print("All collector tests passed!")
