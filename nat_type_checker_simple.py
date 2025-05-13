#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
STUNサーバーを使用してNATタイプを検出するシンプルなプログラム
"""

import stun
import socket
import logging

def check_nat_type():
    """
    STUNプロトコルを使用してNATタイプを検出する

    Returns:
        str: 検出されたNATタイプ
    """
    try:
        nat_type, external_ip, external_port = stun.get_ip_info()
        print(f"NAT Type: {nat_type}")
        print(f"External IP: {external_ip}")
        print(f"External Port: {external_port}")
        return nat_type
    except Exception as e:
        print(f"エラーが発生しました: {e}")
        return None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    nat_type = check_nat_type()
    
    if nat_type:
        if nat_type in [stun.FullCone, stun.RestricNAT, stun.RestricPortNAT]:
            print("このNATはEIM (Endpoint Independent Mapping)の特性を持っています")
        elif nat_type == stun.SymmetricNAT:
            print("このNATはEDM (Endpoint Dependent Mapping)の特性を持っています")
        else:
            print(f"不明なNATタイプです: {nat_type}")