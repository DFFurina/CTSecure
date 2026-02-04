# config.py - 配置加载与保存模块
"""
配置加载与保存模块

负责从 YAML/JSON 文件加载配置，提供全局 CONFIG 和 WHITELIST。
支持配置校验、端口范围检查，并支持持久化保存。
"""

import yaml
import json
import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

CONFIG: Dict[str, Any] = {}  # 全局配置字典
WHITELIST: Dict[str, list] = {  # 全局白名单
    "whitelist_ips": [],
    "whitelist_uas": []
}


def load_config(file_path: str = 'config.yaml') -> None:
    """
    加载主配置和白名单。

    Args:
        file_path: 配置文件的路径，默认为 'config.yaml'

    Raises:
        ValueError: 缺少必填项或端口无效
        RuntimeError: 加载失败
    """
    global CONFIG, WHITELIST

    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"配置文件不存在: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            new_config = yaml.safe_load(f) or {}

        # 必填项检查
        required_keys = ['listen', 'domains']
        for key in required_keys:
            if key not in new_config:
                raise ValueError(f"配置文件缺少必填项: {key}")

        # 端口校验
        http_port = new_config.get('listen', {}).get('http_port', 80)
        https_port = new_config.get('listen', {}).get('https_port', 443)
        if not (1 <= http_port <= 65535 and 1 <= https_port <= 65535):
            raise ValueError("端口号必须在1-65535之间")

        CONFIG.clear()
        CONFIG.update(new_config)
        logger.info("主配置加载完成")

    except Exception as e:
        logger.error(f"配置加载失败: {e}", exc_info=True)
        raise RuntimeError(f"配置加载失败: {e}")

    # 加载白名单（可选文件）
    whitelist_path = 'whitelist.json'
    if os.path.exists(whitelist_path):
        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                WHITELIST.update(json.load(f))
            logger.info("白名单加载完成")
        except Exception as e:
            logger.warning(f"白名单加载失败，使用默认空值: {e}")
    else:
        logger.info("未找到 whitelist.json，使用默认空白名单")


def save_config(file_path: str = 'config.yaml') -> None:
    """
    保存当前 CONFIG 到 yaml 文件。

    Args:
        file_path: 保存路径，默认为 'config.yaml'
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump(CONFIG, f, allow_unicode=True, sort_keys=False)
        logger.info(f"配置已保存到 {file_path}")
    except Exception as e:
        logger.error(f"保存配置失败: {e}", exc_info=True)