#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pystun3ライブラリの定数名を確認するスクリプト
"""

import stun
import inspect

# stunモジュールの属性を表示
print("stunモジュールの属性:")
for name in dir(stun):
    if not name.startswith('__'):
        value = getattr(stun, name)
        if not inspect.ismodule(value) and not inspect.isfunction(value) and not inspect.isclass(value):
            print(f"{name} = {value}")