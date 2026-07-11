"""读取项目根目录的 config.json(数据库等连接配置)。

复制 config.example.json 为 config.json 并填入真实凭据。config.json 不应提交。
"""
from __future__ import annotations

import json
import os

from .config import BASE_DIR

CONFIG_JSON = os.path.join(BASE_DIR, "config.json")


def load_settings() -> dict:
    if os.path.exists(CONFIG_JSON):
        with open(CONFIG_JSON, encoding="utf-8") as f:
            return json.load(f)
    return {}
