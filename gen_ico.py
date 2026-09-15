#!/usr/bin/env python3
"""直接用扩展里的品牌图标生成 ICO（银狐防护 shields/icon128.png -> shield.ico）。
保持扩展原有蓝盾+金勾视觉，不做任何重绘。"""
from PIL import Image

SRC = "D:/silverfox-guard/icons/icon128.png"
DST = "D:/silverfox-envscan/shield.ico"

src = Image.open(SRC).convert("RGBA")
# 源图标应是 128x128；以它为基础缩放多尺寸
sizes = [16, 32, 48, 64, 128, 256]
frames = []
for s in sizes:
    if s == 128:
        frames.append(src.copy())
    else:
        frames.append(src.resize((s, s), Image.LANCZOS))

# Pillow ICO sizes 参数需显式元组列表
src.save(DST, sizes=[(s, s) for s in sizes])
print("saved", DST, "from", SRC, src.size)
