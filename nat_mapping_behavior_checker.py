#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
複数のSTUNサーバーにリクエストを送信し、NATのマッピング動作（EIMかEDM）を判断するプログラム
"""

import socket
import struct
import random
import time
import logging
import binascii
import argparse
from typing import Tuple, List, Dict, Optional

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
    ("stun.ekiga.net", 3478),
    ("stun.ideasip.com", 3478),
    ("stun.schlund.de", 3478),
    ("stun.stunprotocol.org", 3478),
    ("stun.voiparound.com", 3478),
    ("stun.voipbuster.com", 3478),
    ("stun.voipstunt.com", 3478),
    ("stun.voxgratia.org", 3478)
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

    def get_external_address(self, stun_host: str, stun_port: int) -> Tuple[Optional[str], Optional[int]]:
        """
        指定されたSTUNサーバーに問い合わせて外部アドレスを取得する

        Args:
            stun_host: STUNサーバーのホスト名
            stun_port: STUNサーバーのポート番号

        Returns:
            Tuple[Optional[str], Optional[int]]: 外部IPアドレスとポート
        """
        try:
            # UDPソケットを作成
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # 送信元ポートを設定（0の場合はOSが自動的に割り当て）
            sock.bind(('0.0.0.0', self.source_port))
            
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
            return external_ip, external_port
            
        except socket.timeout:
            self.logger.error(f"タイムアウト: {stun_host}:{stun_port}")
        except socket.gaierror:
            self.logger.error(f"ホスト名解決エラー: {stun_host}")
        except Exception as e:
            self.logger.error(f"エラー: {e}")
        
        return None, None

def check_nat_mapping_behavior(num_servers: int = 3, source_port: int = 0) -> None:
    """
    NATのマッピング動作（EIMかEDM）を判断する

    Args:
        num_servers: テストに使用するSTUNサーバーの数
        source_port: 送信元ポート（0の場合はランダム）
    """
    # ロガーの設定
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger('NatChecker')
    
    # 使用するSTUNサーバーをランダムに選択
    selected_servers = random.sample(STUN_SERVERS, min(num_servers, len(STUN_SERVERS)))
    
    # STUNクライアントを作成
    stun_client = StunClient(source_port=source_port)
    
    # 各サーバーに問い合わせて外部アドレスを取得
    results = []
    
    for i, (stun_host, stun_port) in enumerate(selected_servers):
        logger.info(f"STUNサーバー {i+1}/{len(selected_servers)}: {stun_host}:{stun_port} に問い合わせ中...")
        external_ip, external_port = stun_client.get_external_address(stun_host, stun_port)
        
        if external_ip and external_port:
            logger.info(f"外部アドレス: {external_ip}:{external_port}")
            results.append((stun_host, stun_port, external_ip, external_port))
        else:
            logger.warning(f"STUNサーバー {stun_host}:{stun_port} からの応答を取得できませんでした")
    
    # 結果を分析
    if len(results) < 2:
        logger.error("十分な数のSTUNサーバーから応答を得られませんでした。少なくとも2つのサーバーからの応答が必要です。")
        return
    
    # 外部ポートが同じかどうかを確認
    ports = [port for _, _, _, port in results]
    ips = [ip for _, _, ip, _ in results]
    
    # 結果を表示
    logger.info("\n結果:")
    for i, (stun_host, stun_port, external_ip, external_port) in enumerate(results):
        logger.info(f"サーバー {i+1}: {stun_host}:{stun_port} -> {external_ip}:{external_port}")
    
    # 判定
    if len(set(ports)) == 1 and len(set(ips)) == 1:
        logger.info("\n判定: EIM (Endpoint Independent Mapping)")
        logger.info("同じローカルIPとポートから送信されるパケットは、宛先に関係なく常に同じ外部IPとポートにマッピングされています。")
    else:
        logger.info("\n判定: EDM (Endpoint Dependent Mapping)")
        logger.info("宛先が変わると、異なる外部IPやポートにマッピングされています。")
        
        # さらに詳細な分析
        if len(set(ips)) == 1 and len(set(ports)) > 1:
            logger.info("詳細: Address and Port Dependent Mapping")
            logger.info("宛先ポートが変わると、異なる外部ポートにマッピングされています。")
        elif len(set(ips)) > 1:
            logger.info("詳細: Address Dependent Mapping")
            logger.info("宛先IPが変わると、異なる外部IPにマッピングされています。")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='NATのマッピング動作（EIMかEDM）を判断するプログラム')
    parser.add_argument('-n', '--num-servers', type=int, default=3, help='テストに使用するSTUNサーバーの数（デフォルト: 3）')
    parser.add_argument('-p', '--port', type=int, default=0, help='送信元ポート（デフォルト: ランダム）')
    args = parser.parse_args()
    
    check_nat_mapping_behavior(num_servers=args.num_servers, source_port=args.port)