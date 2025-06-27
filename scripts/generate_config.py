#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置文件生成脚本
用于生成 AdGuard Home 的配置文件，包括白名单模式和黑名单模式
"""

import os
import sys
import json
import logging
import datetime
from typing import Dict, List
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# Python 3.9+ 标准库 zoneinfo，若为 Python 3.8- 请使用 pytz
try:
    from zoneinfo import ZoneInfo
    CN_TZ = ZoneInfo("Asia/Shanghai")
except ImportError:
    raise RuntimeError("请使用 Python 3.9 及以上，或用 pytz 兼容代码")

# 避免循环导入
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import extract_domains

# 常量配置
DEFAULT_CN_DNS = ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
DEFAULT_FOREIGN_DNS = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
ALLOWED_TLD = ['cn', 'hk', 'mo', 'tw', 'jp', 'kr', 'sg']

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('generate_config.log', encoding='utf-8')
    ]
)
logger = logging.getLogger('generate_config')


def now_beijing():
    """返回北京时间字符串"""
    return datetime.datetime.now(CN_TZ).strftime('%Y-%m-%d %H:%M:%S')


def load_config() -> dict:
    """加载配置文件"""
    config_path = os.path.join('config', 'config.json')
    if not os.path.exists(config_path):
        config = {
            "sources": {
                "cn_domains": [
                    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaDomain.yaml",
                    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaMedia.yaml",
                    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.yaml",
                    "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
                ],
                "foreign_domains": [
                    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Proxy/Proxy_Domain.yaml",
                    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyGFWlist.yaml",
                    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyMedia.yaml",
                    "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
                ]
            }
        }
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logger.info(f"已创建默认配置文件 {config_path}")
    else:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    return config


def process_sources(sources, custom_file=None) -> set:
    """处理源列表，下载并提取域名"""
    all_domains = set()

    def process_single_source(source):
        content = extract_domains.download_file(source)
        if content:
            domains = extract_domains.extract_domains_from_file(content, source)
            logger.info(f"从 {source} 中提取了 {len(domains)} 个域名")
            return domains
        return set()

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = executor.map(process_single_source, sources)
        for domains in results:
            all_domains.update(domains)

    if custom_file and os.path.exists(custom_file):
        custom_domains = extract_domains.read_custom_domains(custom_file)
        logger.info(f"从自定义文件中读取了 {len(custom_domains)} 个域名")
        all_domains.update(custom_domains)

    return all_domains


def read_custom_domain_dns(file_path: str) -> Dict[str, List[str]]:
    """读取自定义域名DNS配置"""
    custom_dns = {}
    if not os.path.exists(file_path):
        logger.error(f"自定义域名DNS文件不存在: {file_path}")
        return custom_dns

    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if ':' not in line:
                logger.error(f"第 {line_num} 行格式错误，缺少冒号: {line}")
                continue

            domain, dns_list = line.split(':', 1)
            domain = domain.strip()
            dns_servers = [dns.strip() for dns in dns_list.split(',') if dns.strip()]

            if not domain:
                logger.error(f"第 {line_num} 行域名为空")
                continue
            if not dns_servers:
                logger.error(f"第 {line_num} 行DNS服务器为空")
                continue

            # 通配符支持
            if domain.startswith('*'):
                domain = domain.lstrip('*.')  # 去除通配符前缀
                if not extract_domains.is_valid_domain(domain):
                    logger.error(f"第 {line_num} 行通配符域名格式无效: {domain}")
                    continue
                logger.info(f"添加通配符DNS规则: {domain} -> {dns_servers}")
                custom_dns[domain] = dns_servers
                continue

            # 顶级域名支持
            if not extract_domains.is_valid_domain(domain) and domain not in ALLOWED_TLD:
                logger.error(f"第 {line_num} 行域名格式无效: {domain}")
                continue

            custom_dns[domain] = dns_servers
            logger.info(f"添加自定义DNS规则: {domain} -> {dns_servers}")

    logger.info(f"从自定义DNS文件中读取了 {len(custom_dns)} 条规则")
    return custom_dns


def remove_duplicates_in_list(domains):
    """去重域名列表"""
    initial_count = len(domains)
    unique_domains = set(domains)
    if len(unique_domains) < initial_count:
        logger.info(f"从列表中移除了 {initial_count - len(unique_domains)} 个重复域名")
    return unique_domains


def main():
    config = load_config()
    cn_dns = extract_domains.read_dns_servers(os.path.join('config', 'cn_dns.txt'), DEFAULT_CN_DNS)
    foreign_dns = extract_domains.read_dns_servers(os.path.join('config', 'foreign_dns.txt'), DEFAULT_FOREIGN_DNS)
    custom_domain_dns = read_custom_domain_dns(os.path.join('config', 'custom_domain_dns.txt'))

    logger.info(f"使用国内DNS服务器: {cn_dns}")
    logger.info(f"使用国外DNS服务器: {foreign_dns}")
    logger.info(f"自定义域名DNS规则数: {len(custom_domain_dns)}")

    cn_sources = config.get('sources', {}).get('cn_domains', [])
    foreign_sources = config.get('sources', {}).get('foreign_domains', [])

    logger.info("开始提取国内域名...")
    cn_domains = process_sources(cn_sources, os.path.join('config', 'custom_cn_domains.txt'))
    logger.info("开始提取国外域名...")
    foreign_domains = process_sources(foreign_sources, os.path.join('config', 'custom_foreign_domains.txt'))

    logger.info("对国内域名列表进行去重...")
    cn_domains = remove_duplicates_in_list(cn_domains)
    logger.info(f"去重后国内域名数量: {len(cn_domains)}")

    logger.info("对国外域名列表进行去重...")
    foreign_domains = remove_duplicates_in_list(foreign_domains)
    logger.info(f"去重后国外域名数量: {len(foreign_domains)}")

    # ==== 生成配置文件 ====
    # 示例调用：write_to_file(os.path.join('dist', 'gn.txt'), whitelist_config_single)

    logger.info("配置文件生成完成")


if __name__ == "__main__":
    main()