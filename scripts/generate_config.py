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
from typing import Dict, List, Tuple
from collections import defaultdict

# Python 3.9+ 标准库 zoneinfo，若为 Python 3.8- 请使用 pytz
try:
    from zoneinfo import ZoneInfo
    CN_TZ = ZoneInfo("Asia/Shanghai")
except ImportError:
    raise RuntimeError("请使用 Python 3.9 及以上，或用 pytz 兼容代码")

# 避免循环导入
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import extract_domains

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
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
    for source in sources:
        content = extract_domains.download_file(source)
        if content:
            domains = extract_domains.extract_domains_from_file(content, source)
            logger.info(f"从 {source} 中提取了 {len(domains)} 个域名")
            all_domains.update(domains)
    if custom_file and os.path.exists(custom_file):
        custom_domains = extract_domains.read_custom_domains(custom_file)
        logger.info(f"从自定义文件中读取了 {len(custom_domains)} 个域名")
        all_domains.update(custom_domains)
    return all_domains

def read_custom_domain_dns(file_path: str):
    """
    返回自定义DNS规则的分组列表和域名到dns的映射。
    分组列表: [([domain1, domain2, ...], [dns1, dns2, ...]), ...]
    域名到dns的映射: {domain: [dns1, dns2, ...], ...}
    """
    grouped_rules = []
    domain_dns_map = {}
    if not os.path.exists(file_path):
        logger.info(f"自定义域名DNS文件不存在: {file_path}")
        return grouped_rules, domain_dns_map
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' not in line:
                logger.warning(f"第 {line_num} 行格式错误，缺少冒号: {line}")
                continue
            parts = line.split(':', 1)
            domains_part = parts[0].strip()
            dns_servers = [dns.strip() for dns in parts[1].split(',') if dns.strip()]
            if not domains_part or not dns_servers:
                continue
            domains = [d.strip() for d in domains_part.split('/') if d.strip()]
            grouped_rules.append((domains, dns_servers))
            for domain in domains:
                # 通配符支持，直接放行
                domain_dns_map[domain] = dns_servers
                logger.info(f"添加自定义DNS规则: {domain} -> {dns_servers}")
    logger.info(f"从自定义DNS文件中读取了 {len(domain_dns_map)} 条规则（{len(grouped_rules)} 组）")
    return grouped_rules, domain_dns_map

def group_domains_by_dns(domain_set, dns_list):
    dns_tuple = tuple(dns_list)
    result = defaultdict(list)
    for domain in sorted(domain_set):
        result[dns_tuple].append(domain)
    return result

def generate_whitelist_config_single(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns_map=None):
    config_lines = []
    config_lines.append("# AdGuard Home DNS 分流配置 - 白名单模式（逐条规则）")
    config_lines.append(f"# 自动生成于 {now_beijing()}")
    config_lines.append("# 白名单模式：命中国内域名走国内DNS，其他走国外DNS")
    if custom_domain_dns_map:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    config_lines.append("# 默认上游DNS服务器（国外）")
    for dns in foreign_dns:
        config_lines.append(dns)
    config_lines.append("")
    if custom_domain_dns_map:
        config_lines.append("#" + "="*50)
        config_lines.append(f"# 自定义域名DNS规则（逐条规则输出）")
        config_lines.append("#" + "="*50)
        for domain, dns_list in sorted(custom_domain_dns_map.items()):
            config_lines.append(f"[/{domain}/]{' '.join(dns_list)}")
        config_lines.append("")
    cn_domains_filtered = cn_domains - set(custom_domain_dns_map.keys()) if custom_domain_dns_map else cn_domains
    config_lines.append("#" + "="*50)
    config_lines.append(f"# 国内域名规则（共 {len(cn_domains_filtered)} 个域名，逐条规则）")
    if custom_domain_dns_map and len(cn_domains) != len(cn_domains_filtered):
        config_lines.append(f"# 已排除 {len(cn_domains) - len(cn_domains_filtered)} 个自定义DNS域名")
    config_lines.append("#" + "="*50)
    for domain in sorted(cn_domains_filtered):
        config_lines.append(f"[/{domain}/]{' '.join(cn_dns)}")
    return '\n'.join(config_lines)

def generate_blacklist_config_single(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns_map=None):
    config_lines = []
    config_lines.append("# AdGuard Home DNS 分流配置 - 黑名单模式（逐条规则）")
    config_lines.append(f"# 自动生成于 {now_beijing()}")
    config_lines.append("# 黑名单模式：命中国外域名走国外DNS，其他走国内DNS")
    if custom_domain_dns_map:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    config_lines.append("# 默认上游DNS服务器（国内）")
    for dns in cn_dns:
        config_lines.append(dns)
    config_lines.append("")
    if custom_domain_dns_map:
        config_lines.append("#" + "="*50)
        config_lines.append(f"# 自定义域名DNS规则（逐条规则输出）")
        config_lines.append("#" + "="*50)
        for domain, dns_list in sorted(custom_domain_dns_map.items()):
            config_lines.append(f"[/{domain}/]{' '.join(dns_list)}")
        config_lines.append("")
    foreign_domains_filtered = foreign_domains - set(custom_domain_dns_map.keys()) if custom_domain_dns_map else foreign_domains
    config_lines.append("#" + "="*50)
    config_lines.append(f"# 国外域名规则（共 {len(foreign_domains_filtered)} 个域名，逐条规则）")
    if custom_domain_dns_map and len(foreign_domains) != len(foreign_domains_filtered):
        config_lines.append(f"# 已排除 {len(foreign_domains) - len(foreign_domains_filtered)} 个自定义DNS域名")
    config_lines.append("#" + "="*50)
    for domain in sorted(foreign_domains_filtered):
        config_lines.append(f"[/{domain}/]{' '.join(foreign_dns)}")
    return '\n'.join(config_lines)

def generate_whitelist_config_grouped(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns_grouped=None, custom_domain_dns_map=None):
    config_lines = []
    config_lines.append("# AdGuard Home DNS 分流配置 - 白名单模式")
    config_lines.append(f"# 自动生成于 {now_beijing()}")
    config_lines.append("# 白名单模式：命中国内域名走国内DNS，其他走国外DNS")
    if custom_domain_dns_grouped:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    config_lines.append("# 默认上游DNS服务器（国外）")
    for dns in foreign_dns:
        config_lines.append(dns)
    config_lines.append("")
    if custom_domain_dns_grouped:
        config_lines.append("#" + "="*50)
        config_lines.append(f"# 自定义域名DNS规则（分组合并输出）")
        config_lines.append("#" + "="*50)
        for domains, dns_list in custom_domain_dns_grouped:
            domains_str = '/'.join(domains)
            dns_str = ' '.join(dns_list)
            config_lines.append(f"[/{domains_str}/] {dns_str}")
        config_lines.append("")
    custom_domains_set = set(custom_domain_dns_map.keys()) if custom_domain_dns_map else set()
    cn_domains_filtered = cn_domains - custom_domains_set
    grouped = group_domains_by_dns(cn_domains_filtered, cn_dns)
    config_lines.append("#" + "="*50)
    config_lines.append(f"# 国内域名规则（合并）")
    config_lines.append("#" + "="*50)
    for dns_tuple, domains in grouped.items():
        if not domains: continue
        domains_str = '/'.join(domains)
        dns_str = ' '.join(dns_tuple)
        config_lines.append(f"[/{domains_str}/] {dns_str}")
    return '\n'.join(config_lines)

def generate_blacklist_config_grouped(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns_grouped=None, custom_domain_dns_map=None):
    config_lines = []
    config_lines.append("# AdGuard Home DNS 分流配置 - 黑名单模式")
    config_lines.append(f"# 自动生成于 {now_beijing()}")
    config_lines.append("# 黑名单模式：命中国外域名走国外DNS，其他走国内DNS")
    if custom_domain_dns_grouped:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    config_lines.append("# 默认上游DNS服务器（国内）")
    for dns in cn_dns:
        config_lines.append(dns)
    config_lines.append("")
    if custom_domain_dns_grouped:
        config_lines.append("#" + "="*50)
        config_lines.append(f"# 自定义域名DNS规则（分组合并输出）")
        config_lines.append("#" + "="*50)
        for domains, dns_list in custom_domain_dns_grouped:
            domains_str = '/'.join(domains)
            dns_str = ' '.join(dns_list)
            config_lines.append(f"[/{domains_str}/] {dns_str}")
        config_lines.append("")
    custom_domains_set = set(custom_domain_dns_map.keys()) if custom_domain_dns_map else set()
    foreign_domains_filtered = foreign_domains - custom_domains_set
    grouped = group_domains_by_dns(foreign_domains_filtered, foreign_dns)
    config_lines.append("#" + "="*50)
    config_lines.append(f"# 国外域名规则（合并）")
    config_lines.append("#" + "="*50)
    for dns_tuple, domains in grouped.items():
        if not domains: continue
        domains_str = '/'.join(domains)
        dns_str = ' '.join(dns_tuple)
        config_lines.append(f"[/{domains_str}/] {dns_str}")
    return '\n'.join(config_lines)

def remove_duplicates_in_list(domains):
    initial_count = len(domains)
    unique_domains = set(domains)
    if len(unique_domains) < initial_count:
        logger.info(f"从列表中移除了 {initial_count - len(unique_domains)} 个重复域名")
    return unique_domains

def main():
    config = load_config()
    default_cn_dns = ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
    default_foreign_dns = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
    cn_dns = extract_domains.read_dns_servers(os.path.join('config', 'cn_dns.txt'), default_cn_dns)
    foreign_dns = extract_domains.read_dns_servers(os.path.join('config', 'foreign_dns.txt'), default_foreign_dns)
    custom_domain_dns_grouped, custom_domain_dns_map = read_custom_domain_dns(os.path.join('config', 'custom_domain_dns.txt'))
    logger.info(f"使用国内DNS服务器: {cn_dns}")
    logger.info(f"使用国外DNS服务器: {foreign_dns}")
    logger.info(f"自定义域名DNS规则数: {len(custom_domain_dns_map)}")
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
    # ==== 生成并保存4个分流文件 ====
    logger.info("生成白名单模式配置文件（逐条规则）...")
    whitelist_config_single = generate_whitelist_config_single(
        cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns_map
    )
    logger.info("生成白名单模式配置文件（合并规则）...")
    whitelist_config_grouped = generate_whitelist_config_grouped(
        cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns_grouped, custom_domain_dns_map
    )
    logger.info("生成黑名单模式配置文件（逐条规则）...")
    blacklist_config_single = generate_blacklist_config_single(
        cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns_map
    )
    logger.info("生成黑名单模式配置文件（合并规则）...")
    blacklist_config_grouped = generate_blacklist_config_grouped(
        cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns_grouped, custom_domain_dns_map
    )
    os.makedirs('dist', exist_ok=True)
    with open(os.path.join('dist', 'gn.txt'), 'w', encoding='utf-8') as f:
        f.write(whitelist_config_single)
    with open(os.path.join('dist', 'gn_grouped.txt'), 'w', encoding='utf-8') as f:
        f.write(whitelist_config_grouped)
    with open(os.path.join('dist', 'gw.txt'), 'w', encoding='utf-8') as f:
        f.write(blacklist_config_single)
    with open(os.path.join('dist', 'gw_grouped.txt'), 'w', encoding='utf-8') as f:
        f.write(blacklist_config_grouped)
    with open(os.path.join('dist', 'cn_domains.txt'), 'w', encoding='utf-8') as f:
        for domain in sorted(cn_domains):
            f.write(f"{domain}\n")
    with open(os.path.join('dist', 'foreign_domains.txt'), 'w', encoding='utf-8') as f:
        for domain in sorted(foreign_domains):
            f.write(f"{domain}\n")
    if custom_domain_dns_map:
        with open(os.path.join('dist', 'custom_domain_dns_debug.txt'), 'w', encoding='utf-8') as f:
            for domain, dns_list in sorted(custom_domain_dns_map.items()):
                f.write(f"{domain}: {', '.join(dns_list)}\n")
    logger.info("配置文件生成完成")
    logger.info(f"白名单模式：共 {len(cn_domains)} 个国内域名")
    logger.info(f"黑名单模式：共 {len(foreign_domains)} 个国外域名")
    logger.info(f"自定义域名DNS：共 {len(custom_domain_dns_map)} 个域名")
    if custom_domain_dns_map:
        cn_overridden = len(cn_domains.intersection(set(custom_domain_dns_map.keys())))
        foreign_overridden = len(foreign_domains.intersection(set(custom_domain_dns_map.keys())))
        if cn_overridden > 0:
            logger.info(f"自定义DNS覆盖了 {cn_overridden} 个国内域名")
        if foreign_overridden > 0:
            logger.info(f"自定义DNS覆盖了 {foreign_overridden} 个国外域名")

if __name__ == "__main__":
    main()