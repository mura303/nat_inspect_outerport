#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NATの外部ポート割当状況を調べるプログラム
100個のUDP送信元ポートを使って外部ポート割当状況を調査する
"""

import socket
import struct
import random
import time
import logging
import binascii
import argparse
from typing import Tuple, List, Dict, Optional
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

# STUNメッセージタイプ
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
BINDING_ERROR_RESPONSE = 0x0111

# STUNメッセージ属性
MAPPED_ADDRESS = 0x0001
XOR_MAPPED_ADDRESS = 0x0020
SOFTWARE = 0x8022
FINGERPRINT = 0x8028

# STUNマジッククッキー
MAGIC_COOKIE = 0x2112A442

# パブリックSTUNサーバーリスト
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun3.l.google.com", 19302),
    ("stun4.l.google.com", 19302),
]

class StunClient:
    """STUNクライアントクラス"""

    def __init__(self, source_port: int = 0, timeout: int = 2):
        """
        STUNクライアントの初期化

        Args:
            source_port: 送信元ポート（0の場合はランダム）
            timeout: タイムアウト秒数
        """
        self.source_port = source_port
        self.timeout = timeout
        self.logger = logging.getLogger('StunClient')

    def create_binding_request(self) -> bytes:
        """
        STUNバインディングリクエストメッセージを作成する

        Returns:
            bytes: STUNバインディングリクエストメッセージ
        """
        # トランザクションID（96ビットのランダム値）
        transaction_id = random.randbytes(12)
        
        # STUNメッセージヘッダー（20バイト）
        # メッセージタイプ（2バイト）+ メッセージ長（2バイト）+ マジッククッキー（4バイト）+ トランザクションID（12バイト）
        header = struct.pack('>HHI12s', BINDING_REQUEST, 0, MAGIC_COOKIE, transaction_id)
        
        # ソフトウェア属性を追加（オプション）
        software = b'Python STUN Client'
        software_padded = software + (b'\x00' * (4 - len(software) % 4) if len(software) % 4 else b'')
        software_attr = struct.pack('>HH', SOFTWARE, len(software)) + software_padded
        
        # メッセージ長を更新
        message_length = len(software_attr)
        header = struct.pack('>HHI12s', BINDING_REQUEST, message_length, MAGIC_COOKIE, transaction_id)
        
        return header + software_attr

    def parse_binding_response(self, data: bytes) -> Tuple[Optional[str], Optional[int]]:
        """
        STUNバインディングレスポンスを解析する

        Args:
            data: STUNバインディングレスポンスデータ

        Returns:
            Tuple[Optional[str], Optional[int]]: 外部IPアドレスとポート
        """
        if len(data) < 20:
            self.logger.error("レスポンスが短すぎます")
            return None, None
        
        # ヘッダーを解析
        message_type, message_length, magic_cookie = struct.unpack('>HHI', data[:8])
        
        if message_type != BINDING_RESPONSE:
            self.logger.error(f"予期しないメッセージタイプ: {message_type}")
            return None, None
        
        if magic_cookie != MAGIC_COOKIE:
            self.logger.error("マジッククッキーが一致しません")
            return None, None
        
        # 属性を解析
        pos = 20  # ヘッダーの後から開始
        external_ip = None
        external_port = None
        
        while pos < len(data):
            if pos + 4 > len(data):
                break
            
            attr_type, attr_length = struct.unpack('>HH', data[pos:pos+4])
            pos += 4
            
            if attr_type == MAPPED_ADDRESS:
                if attr_length >= 8:  # 少なくとも8バイト必要
                    family, port = struct.unpack('>xBH', data[pos:pos+4])
                    if family == 0x01:  # IPv4
                        ip = socket.inet_ntoa(data[pos+4:pos+8])
                        external_ip = ip
                        external_port = port
            
            elif attr_type == XOR_MAPPED_ADDRESS:
                if attr_length >= 8:  # 少なくとも8バイト必要
                    family, xport = struct.unpack('>xBH', data[pos:pos+4])
                    if family == 0x01:  # IPv4
                        # XORされたポートをデコード
                        port = xport ^ (MAGIC_COOKIE >> 16)
                        
                        # XORされたIPアドレスをデコード
                        xip = struct.unpack('>I', data[pos+4:pos+8])[0]
                        ip_int = xip ^ MAGIC_COOKIE
                        ip = socket.inet_ntoa(struct.pack('>I', ip_int))
                        
                        external_ip = ip
                        external_port = port
            
            # 次の属性へ（4バイト境界に合わせる）
            pos += attr_length
            if attr_length % 4:
                pos += 4 - (attr_length % 4)
        
        return external_ip, external_port

    def get_external_address(self, stun_host: str, stun_port: int, local_port: int = 0) -> Tuple[Optional[str], Optional[int], Optional[int]]:
        """
        指定されたSTUNサーバーに問い合わせて外部アドレスを取得する

        Args:
            stun_host: STUNサーバーのホスト名
            stun_port: STUNサーバーのポート番号
            local_port: 使用するローカルポート（0の場合はOSが自動的に割り当て）

        Returns:
            Tuple[Optional[str], Optional[int], Optional[int]]: 外部IPアドレス、外部ポート、ローカルポート
        """
        try:
            # UDPソケットを作成
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # 送信元ポートを設定
            sock.bind(('0.0.0.0', local_port))
            
            # 使用されたローカルポートを取得
            _, actual_local_port = sock.getsockname()
            
            # STUNサーバーのIPアドレスを解決
            stun_ip = socket.gethostbyname(stun_host)
            
            # バインディングリクエストを作成して送信
            request = self.create_binding_request()
            sock.sendto(request, (stun_ip, stun_port))
            
            # レスポンスを受信
            data, addr = sock.recvfrom(2048)
            
            # レスポンスを解析
            external_ip, external_port = self.parse_binding_response(data)
            
            sock.close()
            return external_ip, external_port, actual_local_port
            
        except socket.timeout:
            self.logger.error(f"タイムアウト: {stun_host}:{stun_port}")
        except socket.gaierror:
            self.logger.error(f"ホスト名解決エラー: {stun_host}")
        except Exception as e:
            self.logger.error(f"エラー: {e}")
        
        return None, None, None

def check_port_allocation(num_ports: int = 100, start_port: int = 10000, stun_server_index: int = 0) -> None:
    """
    NATの外部ポート割当状況を調べる

    Args:
        num_ports: テストするポートの数
        start_port: 開始ローカルポート番号
        stun_server_index: 使用するSTUNサーバーのインデックス
    """
    # ロガーの設定
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger('PortAllocationChecker')
    
    # STUNサーバーを選択
    if stun_server_index >= len(STUN_SERVERS):
        stun_server_index = 0
    stun_host, stun_port = STUN_SERVERS[stun_server_index]
    logger.info(f"STUNサーバー: {stun_host}:{stun_port} を使用します")
    
    # STUNクライアントを作成
    stun_client = StunClient()
    
    # 結果を格納するリスト
    results = []
    
    # 各ポートについてテスト
    for i in range(num_ports):
        local_port = start_port + i
        logger.info(f"テスト {i+1}/{num_ports}: ローカルポート {local_port} を使用")
        
        external_ip, external_port, actual_local_port = stun_client.get_external_address(stun_host, stun_port, local_port)
        
        if external_ip and external_port:
            logger.info(f"ローカルポート {actual_local_port} -> 外部アドレス: {external_ip}:{external_port}")
            results.append((actual_local_port, external_port))
        else:
            logger.warning(f"ローカルポート {local_port} の外部アドレスを取得できませんでした")
        
        # サーバーに負荷をかけないよう少し待機
        time.sleep(0.1)
    
    # 結果を分析
    if not results:
        logger.error("テスト結果がありません")
        return
    
    # ローカルポートと外部ポートのリスト
    local_ports = [r[0] for r in results]
    external_ports = [r[1] for r in results]
    
    # 外部ポートの分布を分析
    port_diff = [external_ports[i] - external_ports[i-1] if i > 0 else 0 for i in range(len(external_ports))]
    port_diff = port_diff[1:]  # 最初の要素（0）を除外
    
    # 外部ポートの連続性を分析
    consecutive_count = 0
    for i in range(1, len(external_ports)):
        if external_ports[i] == external_ports[i-1] + 1:
            consecutive_count += 1
    
    consecutive_percentage = (consecutive_count / (len(external_ports) - 1)) * 100 if len(external_ports) > 1 else 0
    
    # 外部ポートの重複を分析
    unique_external_ports = set(external_ports)
    duplicate_count = len(external_ports) - len(unique_external_ports)
    duplicate_percentage = (duplicate_count / len(external_ports)) * 100
    
    # 結果を表示
    logger.info("\n分析結果:")
    logger.info(f"テスト数: {len(results)}")
    logger.info(f"外部ポートの最小値: {min(external_ports)}")
    logger.info(f"外部ポートの最大値: {max(external_ports)}")
    logger.info(f"外部ポートの範囲: {max(external_ports) - min(external_ports) + 1}")
    logger.info(f"外部ポートの平均差分: {sum(port_diff) / len(port_diff) if port_diff else 0:.2f}")
    logger.info(f"連続した外部ポートの割合: {consecutive_percentage:.2f}%")
    logger.info(f"重複した外部ポートの数: {duplicate_count}")
    logger.info(f"重複した外部ポートの割合: {duplicate_percentage:.2f}%")
    
    # 外部ポートとローカルポートの関係をプロットする
    plt.figure(figsize=(12, 8))
    
    # 外部ポートとローカルポートの散布図
    plt.subplot(2, 2, 1)
    plt.scatter(local_ports, external_ports)
    plt.xlabel('ローカルポート')
    plt.ylabel('外部ポート')
    plt.title('ローカルポートと外部ポートの関係')
    plt.grid(True)
    
    # 外部ポートのヒストグラム
    plt.subplot(2, 2, 2)
    plt.hist(external_ports, bins=min(30, len(set(external_ports))))
    plt.xlabel('外部ポート')
    plt.ylabel('頻度')
    plt.title('外部ポートの分布')
    plt.grid(True)
    
    # 外部ポートの差分のヒストグラム
    plt.subplot(2, 2, 3)
    if port_diff:
        plt.hist(port_diff, bins=min(20, len(set(port_diff))))
        plt.xlabel('外部ポートの差分')
        plt.ylabel('頻度')
        plt.title('外部ポートの差分の分布')
        plt.grid(True)
    
    # 外部ポートの時系列プロット
    plt.subplot(2, 2, 4)
    plt.plot(range(len(external_ports)), external_ports, marker='o')
    plt.xlabel('テスト番号')
    plt.ylabel('外部ポート')
    plt.title('外部ポートの時系列変化')
    plt.grid(True)
    
    plt.tight_layout()
    plt.savefig('port_allocation_analysis.png')
    logger.info("分析グラフを port_allocation_analysis.png に保存しました")
    
    # 詳細な結果をCSVファイルに保存
    with open('port_allocation_results.csv', 'w') as f:
        f.write('local_port,external_port\n')
        for local_port, external_port in results:
            f.write(f'{local_port},{external_port}\n')
    logger.info("詳細な結果を port_allocation_results.csv に保存しました")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='NATの外部ポート割当状況を調べるプログラム')
    parser.add_argument('-n', '--num-ports', type=int, default=100, help='テストするポートの数（デフォルト: 100）')
    parser.add_argument('-s', '--start-port', type=int, default=10000, help='開始ローカルポート番号（デフォルト: 10000）')
    parser.add_argument('-i', '--server-index', type=int, default=0, help='使用するSTUNサーバーのインデックス（デフォルト: 0）')
    args = parser.parse_args()
    
    check_port_allocation(num_ports=args.num_ports, start_port=args.start_port, stun_server_index=args.server_index)