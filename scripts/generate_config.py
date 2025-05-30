#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置文件生成脚本
用于生成 AdGuard Home 的配置文件，包括白名单模式和黑名单模式

功能说明：
1. 加载配置文件（如果不存在则创建默认配置）；
2. 通过 extract_domains 模块下载并解析国内外域名源，同时支持自定义域名文件；
3. 读取自定义的 DNS 规则文件，格式示例如下：
     domain1.com: dns1, dns2, dns3
     # 注释行被忽略
4. 对读取的域名进行去重，并根据指定的 DNS 服务器分组合并生成配置内容；
5. 保存生成的配置文件：原始输出文件为 gn.txt（白名单模式）与 gw.txt（黑名单模式），
   同时新增生成文件 whitelist_mode.txt 与 blacklist_mode.txt（内容可按需做额外处理）。
6. 同时生成调试用的域名列表与自定义 DNS 文件。
"""

import os
import sys
import json
import logging
import datetime
import urllib.request
from urllib.error import URLError
from typing import Dict, List, Set
from collections import defaultdict

# 将当前脚本所在目录追加到模块搜索路径中，避免因相对路径问题引发导入错误
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import extract_domains

# 配置日志输出
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('generate_config')


def load_config() -> dict:
    """
    加载配置文件，如果不存在则自动创建默认配置文件。
    默认配置文件存放在 config/config.json 中。
    """
    config_path = os.path.join('config', 'config.json')
    if not os.path.exists(config_path):
        config = {
            "sources": {
                "cn_domains": [
                    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaDomain.yaml",
                    "https://raw.githubusercontentChinaMax_Domain.yaml",
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
        logger.info(f"默认配置文件已创建：{config_path}")
    else:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    return config


def process_sources(sources: List[str], custom_file: str = None) -> Set[str]:
    """
    处理域名源列表，下载并提取域名，同时合并自定义域名文件中的域名。
    :param sources: 远程域名源 URL 列表。
    :param custom_file: 自定义域名文件路径（可选）。
    :return: 提取后的域名集合。
    """
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


def read_custom_domain_dns(file_path: str) -> Dict[str, List[str]]:
    """
    读取自定义域名 DNS 规则，文件格式示例如下：
       domain1.com: dns1, dns2, dns3
       # 注释行
    :param file_path: 自定义 DNS 规则文件路径。
    :return: 自定义 DNS 规则的字典映射 {域名: [dns1, dns2, ...]}。
    """
    custom_dns = {}
    if not os.path.exists(file_path):
        logger.info(f"自定义域名DNS文件不存在: {file_path}")
        return custom_dns
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' not in line:
                logger.warning(f"第 {line_num} 行格式错误，缺少冒号: {line}")
                continue
            domain, dns_str = line.split(':', 1)
            domain = domain.strip()
            dns_servers = [dns.strip() for dns in dns_str.split(',') if dns.strip()]
            if not domain:
                logger.warning(f"第 {line_num} 行域名为空")
                continue
            if not dns_servers:
                logger.warning(f"第 {line_num} 行DNS服务器为空")
                continue
            # 验证域名格式，允许常见 TLD 缩写
            if not extract_domains.is_valid_domain(domain) and domain not in ['cn', 'hk', 'mo', 'tw', 'jp', 'kr', 'sg']:
                logger.warning(f"第 {line_num} 行域名格式无效: {domain}")
                continue
            custom_dns[domain] = dns_servers
            logger.info(f"添加自定义DNS规则: {domain} -> {dns_servers}")
    logger.info(f"共读取了 {len(custom_dns)} 条自定义DNS规则")
    return custom_dns


def group_domains_by_dns(domain_set: Set[str], dns_list: List[str]) -> Dict[tuple, List[str]]:
    """
    将域名集合根据指定的 DNS 列表分组合并（同一组 DNS 的域名合并输出）。
    :param domain_set: 域名集合。
    :param dns_list: DNS 服务器列表。
    :return: 分组字典，其键为 DNS 服务器的元组，值为对应的域名列表。
    """
    dns_tuple = tuple(dns_list)
    result = defaultdict(list)
    for domain in sorted(domain_set):
        result[dns_tuple].append(domain)
    return result


def generate_whitelist_config_grouped(cn_domains: Set[str],
                                      foreign_domains: Set[str],
                                      cn_dns: List[str],
                                      foreign_dns: List[str],
                                      custom_domain_dns: Dict[str, List[str]] = None) -> str:
    """
    生成白名单模式配置：
      - 国内域名走国内DNS，其余域名走国外DNS；
      - 自定义 DNS 规则优先输出；
      - 同一组 DNS 的域名合并为一条配置。
    :return: 生成的白名单配置字符串。
    """
    lines = []
    lines.append    lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("# 白名单：国内域名走国内DNS，其余走国外DNS")
    if custom_domain_dns:
        lines.append("# 包含自定义域名DNS规则")
    lines.append("")

    # 默认上游国外 DNS 列表
    lines.append("# 默认上游DNS服务器（国外）")
    lines.extend(foreign_dns)
    lines.append("")

    # 输出自定义 DNS 规则
    if custom_domain_dns:
        lines.append("#" + "=" * 50)
        lines.append(f"# 自定义域名DNS规则（共 {len(custom_domain_dns)} 个域名）")
        lines.append("# 这些规则优先级最高，会覆盖下面的规则")
        lines.append("#" + "=" * 50)
        for domain, dns_list in sorted(custom_domain_dns.items()):
            lines.append(f"[/{domain}/]{' '.join(dns_list)}")
        lines.append("")

    # 对国内域名排除自定义DNS部分
    filtered_cn = cn_domains - set(custom_domain_dns.keys()) if custom_domain_dns else cn_domains
    grouped = group_domains_by_dns(filtered_cn, cn_dns)
    lines.append("#" + "=" * 50)
    lines.append(f"# 国内域名规则（共 {len(filtered_cn)} 个域名，已合并）")
    if custom_domain_dns and len(cn_domains) != len(filtered_cn):
        lines.append(f"# 已排除 {len(cn_domains) - len(filtered_cn)} 个自定义DNS域名")
    lines.append("#" + "=" * 50)
    for dns_tuple, domains in grouped.items():
        if not domains:
            continue
        domains_str = '/'.join(domains)
        dns_str = ' '.join(dns_tuple)
        lines.append(f"[/{domains_str}/]{dns_str}")

    return "\n".join(lines)


def generate_blacklist_config_grouped(cn_domains: Set[str],
                                      foreign_domains: Set[str],
                                      cn_dns: List[str],
                                      foreign_dns: List[str],
                                      custom_domain_dns: Dict[str, List[str]] = None) -> str:
    """
    生成黑名单模式配置：
      - 国外域名走国外DNS，其余域名走国内DNS；
      - 自定义 DNS 规则优先覆盖；
      - 将同一组 DNS 的域名合并输出。
    :return: 生成的黑名单配置字符串。
    """
    lines = []
    lines.append("# AdGuard Home DNS 分流配置 - 黑名单模式")
    lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("# 黑名单：国外域名走国外DNS，其余走国内DNS")
    if custom_domain_dns:
        lines.append("# 包含自定义域名DNS规则")
    lines.append("")

    # 默认上游国内 DNS 列表
    lines.append("# 默认上游DNS服务器（国内）")
    lines.extend(cn_dns)
    lines.append("")

    # 输出自定义 DNS 规则
    if custom_domain_dns:
        lines.append("#" + "=" * 50)
        lines.append(f"# 自定义域名DNS规则（共 {len(custom_domain_dns)} 个域名）")
        lines.append("# 这些规则优先级最高，会覆盖下面的规则")
        lines.append("#" + "=" * 50)
        for domain, dns_list in sorted(custom_domain_dns.items()):
            lines.append(f"[/{domain}/]{' '.join(dns_list)}")
        lines.append("")

    # 对国外域名排除自定义DNS部分
    filtered_foreign = foreign_domains - set(custom_domain_dns.keys()) if custom_domain_dns else foreign_domains
    grouped = group_domains_by_dns(filtered_foreign, foreign_dns)
    lines.append("#" + "=" * 50)
    lines.append(f"# 国外域名规则（共 {len(filtered_foreign)} 个域名，已合并）")
    if custom_domain_dns and len(foreign_domains) != len(filtered_foreign):
        lines.append(f"# 已排除 {len(foreign_domains) - len(filtered_foreign)} 个自定义DNS域名")
    lines.append("#" + "=" * 50)
    for dns_tuple, domains in grouped.items():
        if not domains:
            continue
        domains_str = '/'.join(domains)
        dns_str = ' '.join(dns_tuple)
        lines.append(f"[/{domains_str}/]{dns_str}")

    return "\n".join(lines)


def remove_duplicates_in_list(domains: Set[str]) -> Set[str]:
    """
    对域名集合进行去重并返回唯一域名集合，同时记录去重情况。
    """
    initial_count = len(domains)
    unique_domains = set(domains)
    if len(unique_domains) < initial_count:
        logger.info(f"已去除 {initial_count - len(unique_domains)} 个重复域名")
    return unique_domains


def main():
    """主函数，执行整个配置生成流程"""
    config = load_config()

    # 默认 DNS 服务器设置
    default_cn_dns = ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
    default_foreign_dns = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]

    # 通过配置文件读取 DNS 服务器（支持覆盖默认值）
    cn_dns = extract_domains.read_dns_servers(os.path.join('config', 'cn_dns.txt'), default_cn_dns)
    foreign_dns = extract_domains.read_dns_servers(os.path.join('config', 'foreign_dns.txt'), default_foreign_dns)

    # 读取自定义域名 DNS 规则
    custom_domain_dns = read_custom_domain_dns(os.path.join('config', 'custom_domain_dns.txt'))
    logger.info(f"国内DNS服务器: {cn_dns}")
    logger.info(f"国外DNS服务器: {foreign_dns}")
    logger.info(f"自定义DNS规则数: {len(custom_domain_dns)}")

    # 提取域名源
    cn_sources = config.get('sources', {}).get('cn_domains', [])
    foreign_sources = config.get('sources', {}).get('foreign_domains', [])

    logger.info("开始提取国内域名...")
    cn_domains = process_sources(cn_sources, os.path.join('config', 'custom_cn_domains.txt'))
    logger.info("开始提取国外域名...")
    foreign_domains = process_sources(foreign_sources, os.path.join('config', 'custom_foreign_domains.txt'))

    # 对域名集合去重
    logger.info("正在对国内域名去重...")
    cn_domains = remove_duplicates_in_list(cn_domains)
    logger.info(f"去重后国内域名数：{len(cn_domains)}")
    logger.info("正在对国外域名去重...")
    foreign_domains = remove_duplicates_in_list(foreign_domains)
    logger.info(f"去重后国外域名数：{len(foreign_domains)}")

    # 生成配置内容
    logger.info("生成白名单模式配置...")
    whitelist_config = generate_whitelist_config_grouped(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns)
    logger.info("生成黑名单模式配置...")
    blacklist_config = generate_blacklist_config_grouped(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns)

    # 确保输出目录存在
    os.makedirs('dist', exist_ok=True)

    # 保存原始配置文件 gn.txt 和 gw.txt
    with open(os.path.join('dist', 'gn.txt'), 'w', encoding='utf-8') as f:
        f.write(whitelist_config)
    with open(os.path.join('dist', 'gw.txt'), 'w', encoding='utf-8') as f:
        f.write(blacklist_config)

    # 新增生成 whitelist_mode.txt 和 blacklist_mode.txt（内容示例中增加了额外前缀，可根据需要自定义）
    with open(os.path.join('dist', 'whitelist_mode.txt'), 'w', encoding='utf-8') as f:
        new_whitelist = "【新白名单配置】\n" + whitelist_config
        f.write(new_whitelist)
    with open(os.path.join('dist', 'blacklist_mode.txt'), 'w', encoding='utf-8') as f:
        new_blacklist = "【新黑名单配置】\n" + blacklist_config
        f.write(new_blacklist)

    # 保存辅助调试文件（域名列表与自定义 DNS 规则）
    with open(os.path.join('dist', 'cn_domains.txt'), 'w', encoding='utf-8') as f:
        for domain in sorted(cn_domains):
            f.write(domain + "\n")
    with open(os.path.join('dist', 'foreign_domains.txt'), 'w', encoding='utf-8') as f:
        for domain in sorted(foreign_domains):
            f.write(domain + "\n")
    if custom_domain_dns:
        with open(os.path.join('dist', 'custom_domain_dns_debug.txt'), 'w', encoding='utf-8') as f:
            for domain, dns_list in sorted(custom_domain_dns.items()):
                f.write(f"{domain}: {', '.join(dns_list)}\n")

    logger.info("配置文件生成完成")
    logger.info(f"白名单配置：{len(cn_domains)} 个国内域名")
    logger.info(f"黑名单配置：{len(foreign_domains)} 个国外域名")
    logger.info(f"自定义DNS规则数：{len(custom_domain_dns)}")

    # 统计自定义规则覆盖情况
    if custom_domain_dns:
        cn_overridden = len(cn_domains.intersection(set(custom_domain_dns.keys())))
        foreign_overridden = len(foreign_domains.intersection(set(custom_domain_dns.keys())))
        if cn_overridden > 0:
            logger.info(f"自定义DNS覆盖了 {cn_overridden} 个国内域名")
        if foreign_overridden > 0:
            logger.info(f"自定义DNS覆盖了 {foreign_overridden} 个国外域名")

if __name__ == "__main__":
    main()