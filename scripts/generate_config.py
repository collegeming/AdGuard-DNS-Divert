#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置文件生成脚本
用于生成 AdGuard Home 的配置文件，包括白名单模式和黑名单模式

主要功能：
1. 加载或创建基本配置文件（config/config.json）
2. 下载并解析远程域名规则列表，同时支持自定义域名文件（custom_cn_domains.txt, custom_foreign_domains.txt）
3. 读取自定义DNS规则，格式为 "域名: dns1, dns2, ..." 
4. 根据提取的数据生成两种模式下的配置文件：
   - 白名单模式：国内域名走国内DNS，其余走国外DNS
   - 黑名单模式：国外域名走国外DNS，其余走国内DNS
5. 最后生成配置文件和域名列表（调试用途）到 dist 目录中
"""

import os
import sys
import json
import logging
import datetime
import urllib.request
from urllib.error import URLError
from typing import Dict, List, Set

# 为防止模块循环导入，将当前脚本所在的目录添加到sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import extract_domains  # 此模块负责域名提取及DNS服务器读取等功能

# 配置日志输出
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # 将日志输出到标准输出
    ]
)
logger = logging.getLogger('generate_config')

def load_config() -> dict:
    """加载配置文件，如果不存在则创建默认配置文件
    
    返回:
        config (dict): 包含域名来源的配置数据
    """
    config_path = os.path.join('config', 'config.json')

    if not os.path.exists(config_path):
        # 如果配置文件不存在，则构造默认配置
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
        # 确保配置目录存在
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logger.info(f"已创建默认配置文件 {config_path}")
    else:
        # 如果配置文件存在，则读取它
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    return config

def process_sources(sources, custom_file=None) -> set:
    """处理域名规则来源，下载远程数据并提取域名

    参数:
        sources (list): 包含远程URL的列表
        custom_file (str, 可选): 本地自定义域名文件路径

    返回:
        all_domains (set): 所有提取的域名集合
    """
    all_domains = set()

    # 迭代所有远程数据源
    for source in sources:
        content = extract_domains.download_file(source)
        if content:
            # 提取域名列表
            domains = extract_domains.extract_domains_from_file(content, source)
            logger.info(f"从 {source} 中提取了 {len(domains)} 个域名")
            all_domains.update(domains)

    # 如果提供了自定义文件，并且文件存在，则读取并合并自定义域名
    if custom_file and os.path.exists(custom_file):
        custom_domains = extract_domains.read_custom_domains(custom_file)
        logger.info(f"从自定义文件中读取了 {len(custom_domains)} 个域名")
        all_domains.update(custom_domains)

    return all_domains

def read_custom_domain_dns(file_path: str) -> Dict[str, List[str]]:
    """从文件中读取自定义域名DNS配置
     
    文件格式示例:
        domain1.com: dns1, dns2, dns3
        domain2.com: dns4
        # 注释行
     
    参数:
        file_path (str): 自定义DNS配置文件的路径
     
    返回:
        custom_dns (dict): 键为域名，值为DNS服务器列表字典
    """
    custom_dns = {}

    if not os.path.exists(file_path):
        logger.info(f"自定义域名DNS文件不存在: {file_path}")
        return custom_dns

    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            # 去除首尾空白字符
            line = line.strip()

            # 跳过空行和注释行
            if not line or line.startswith('#'):
                continue

            # 检查格式是否包含冒号
            if ':' not in line:
                logger.warning(f"第 {line_num} 行格式错误，缺少冒号: {line}")
                continue

            parts = line.split(':', 1)
            domain = parts[0].strip()
            # 用逗号分隔DNS服务器并去除多余空白
            dns_servers = [dns.strip() for dns in parts[1].split(',') if dns.strip()]

            if not domain:
                logger.warning(f"第 {line_num} 行域名为空")
                continue

            if not dns_servers:
                logger.warning(f"第 {line_num} 行DNS服务器为空")
                continue

            # 判断域名格式是否正确，允许部分常见TLD
            if not extract_domains.is_valid_domain(domain) and domain not in ['cn', 'hk', 'mo', 'tw', 'jp', 'kr', 'sg']:
                logger.warning(f"第 {line_num} 行域名格式无效: {domain}")
                continue

            custom_dns[domain] = dns_servers
            logger.info(f"添加自定义DNS规则: {domain} -> {dns_servers}")

    logger.info(f"从自定义DNS文件中读取了 {len(custom_dns)} 条规则")
    return custom_dns

def generate_whitelist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns=None) -> str:
    """生成白名单模式配置文件内容

    白名单模式：国内域名使用国内DNS，而其他域名使用国外DNS

    参数:
        cn_domains (set): 国内域名集合
        foreign_domains (set): 国外域名集合
        cn_dns (list): 国内DNS服务器列表
        foreign_dns (list): 国外DNS服务器列表
        custom_domain_dns (dict, 可选): 自定义域名DNS规则字典

    返回:
        配置文件内容 (str)
    """
    config_lines = []

    # 生成文件头的注释信息
    config_lines.append("# AdGuard Home DNS 分流配置 - 白名单模式")
    config_lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config_lines.append("# 白名单模式：命中国内域名走国内DNS，其他走国外DNS")
    if custom_domain_dns:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")

    # 写入默认的上游DNS服务器（国外DNS服务器）
    config_lines.append("# 默认上游DNS服务器（国外）")
    for dns in foreign_dns:
        config_lines.append(dns)
    config_lines.append("")

    # 如果存在自定义DNS规则，则优先添加
    if custom_domain_dns:
        config_lines.append("#" + "=" * 50)
        config_lines.append(f"# 自定义域名DNS规则（共 {len(custom_domain_dns)} 个域名）")
        config_lines.append("# 这些规则优先级最高，会覆盖下面的国内/国外规则")
        config_lines.append("#" + "=" * 50)
        for domain, dns_list in sorted(custom_domain_dns.items()):
            dns_string = ' '.join(dns_list)
            config_lines.append(f"[/{domain}/]{dns_string}")
        config_lines.append("")

    # 排除自定义DNS中已经处理的域名，避免规则重复
    cn_domains_filtered = cn_domains - set(custom_domain_dns.keys()) if custom_domain_dns else cn_domains

    # 添加国内域名规则，使用国内DNS服务器
    config_lines.append("#" + "=" * 50)
    config_lines.append(f"# 国内域名规则（共 {len(cn_domains_filtered)} 个域名）")
    if custom_domain_dns and len(cn_domains) != len(cn_domains_filtered):
        config_lines.append(f"# 已排除 {len(cn_domains) - len(cn_domains_filtered)} 个自定义DNS域名")
    config_lines.append("#" + "=" * 50)
    for domain in sorted(cn_domains_filtered):
        dns_list = ' '.join(cn_dns)
        config_lines.append(f"[/{domain}/]{dns_list}")

    return "\n".join(config_lines)

def generate_blacklist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns=None) -> str:
    """生成黑名单模式配置文件内容

    黑名单模式：国外域名使用国外DNS，而其他域名使用国内DNS

    参数:
        cn_domains (set): 国内域名集合
        foreign_domains (set): 国外域名集合
        cn_dns (list): 国内DNS服务器列表
        foreign_dns (list): 国外DNS服务器列表
        custom_domain_dns (dict, 可选): 自定义域名DNS规则字典

    返回:
        配置文件内容 (str)
    """
    config_lines = []

    # 写入文件头和注释说明
    config_lines.append("# AdGuard Home DNS 分流配置 - 黑名单模式")
    config_lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config_lines.append("# 黑名单模式：命中国外域名走国外DNS，其他走国内DNS")
    if custom_domain_dns:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")

    # 添加默认国内DNS服务器作为上游DNS
    config_lines.append("# 默认上游DNS服务器（国内）")
    for dns in cn_dns:
        config_lines.append(dns)
    config_lines.append("")

    # 优先写入自定义DNS规则
    if custom_domain_dns:
        config_lines.append("#" + "=" * 50)
        config_lines.append(f"# 自定义域名DNS规则（共 {len(custom_domain_dns)} 个域名）")
        config_lines.append("# 这些规则优先级最高，会覆盖下面的国内/国外规则")
        config_lines.append("#" + "=" * 50)
        for domain, dns_list in sorted(custom_domain_dns.items()):
            dns_string = ' '.join(dns_list)
            config_lines.append(f"[/{domain}/]{dns_string}")
        config_lines.append("")

    # 排除已经在自定义DNS中配置的域名后，写入国外域名规则
    foreign_domains_filtered = foreign_domains - set(custom_domain_dns.keys()) if custom_domain_dns else foreign_domains

    # 写入国外域名规则，使用国外DNS服务器
    config_lines.append("#" + "=" * 50)
    config_lines.append(f"# 国外域名规则（共 {len(foreign_domains_filtered)} 个域名）")
    if custom_domain_dns and len(foreign_domains) != len(foreign_domains_filtered):
        config_lines.append(f"# 已排除 {len(foreign_domains) - len(foreign_domains_filtered)} 个自定义DNS域名")
    config_lines.append("#" + "=" * 50)
    for domain in sorted(foreign_domains_filtered):
        dns_list = ' '.join(foreign_dns)
        config_lines.append(f"[/{domain}/]{dns_list}")

    return "\n".join(config_lines)

def debug_domain(domains, domain_to_check):
    """检查指定域名是否存在于域名集合中，并输出调试信息

    参数:
        domains (set): 域名集合
        domain_to_check (str): 要检查的域名
    """
    if domain_to_check in domains:
        logger.info(f"域名 {domain_to_check} 在列表中")
    else:
        logger.info(f"域名 {domain_to_check} 不在列表中")
        # 查找可能的相似域名，并输出调试信息
        similar_domains = [d for d in domains if domain_to_check in d or d in domain_to_check]
        if similar_domains:
            logger.info(f"找到相似域名: {similar_domains}")

def remove_duplicates_in_list(domains):
    """在列表内部去重，返回唯一域名集合

    参数:
        domains (iterable): 初步域名列表
    
    返回:
        unique_domains (set): 去重后的域名集合
    """
    initial_count = len(domains)
    unique_domains = set(domains)
    if len(unique_domains) < initial_count:
        logger.info(f"从列表中移除了 {initial_count - len(unique_domains)} 个重复域名")
    return unique_domains

def main():
    """主函数：加载配置、提取域名、生成配置及保存结果到文件"""
    # 加载配置文件，如果不存在则创建默认配置
    config = load_config()

    # 定义默认DNS服务器列表
    default_cn_dns = ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
    default_foreign_dns = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]

    # 读取DNS服务器配置文件，使用默认值作为备选项
    cn_dns = extract_domains.read_dns_servers(os.path.join('config', 'cn_dns.txt'), default_cn_dns)
    foreign_dns = extract_domains.read_dns_servers(os.path.join('config', 'foreign_dns.txt'), default_foreign_dns)

    # 读取自定义域名DNS规则配置
    custom_domain_dns = read_custom_domain_dns(os.path.join('config', 'custom_domain_dns.txt'))
    logger.info(f"使用国内DNS服务器: {cn_dns}")
    logger.info(f"使用国外DNS服务器: {foreign_dns}")
    logger.info(f"自定义域名DNS规则数: {len(custom_domain_dns)}")

    # 从配置文件中获取各域名列表来源
    cn_sources = config.get('sources', {}).get('cn_domains', [])
    foreign_sources = config.get('sources', {}).get('foreign_domains', [])

    # 下载并提取国内外域名
    logger.info("开始提取国内域名...")
    cn_domains = process_sources(cn_sources, os.path.join('config', 'custom_cn_domains.txt'))
    logger.info("开始提取国外域名...")
    foreign_domains = process_sources(foreign_sources, os.path.join('config', 'custom_foreign_domains.txt'))

    # 对各自域名列表内部去重
    logger.info("对国内域名列表进行去重...")
    cn_domains = remove_duplicates_in_list(cn_domains)
    logger.info(f"去重后国内域名数量: {len(cn_domains)}")

    logger.info("对国外域名列表进行去重...")
    foreign_domains = remove_duplicates_in_list(foreign_domains)
    logger.info(f"去重后国外域名数量: {len(foreign_domains)}")

    # 生成白名单与黑名单配置内容
    logger.info("生成白名单模式配置文件...")
    whitelist_config = generate_whitelist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns)
    logger.info("生成黑名单模式配置文件...")
    blacklist_config = generate_blacklist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns)

    # 确保输出目录存在
    os.makedirs('dist', exist_ok=True)

    # 写入配置文件到 dist 目录
    with open(os.path.join('dist', 'whitelist_mode.txt'), 'w', encoding='utf-8') as f:
        f.write(whitelist_config)

    with open(os.path.join('dist', 'blacklist_mode.txt'), 'w', encoding='utf-8') as f:
        f.write(blacklist_config)

    # 保存域名列表用于调试和验证
    with open(os.path.join('dist', 'cn_domains.txt'), 'w', encoding='utf-8') as f:
        for domain in sorted(cn_domains):
            f.write(f"{domain}\n")

    with open(os.path.join('dist', 'foreign_domains.txt'), 'w', encoding='utf-8') as f:
        for domain in sorted(foreign_domains):
            f.write(f"{domain}\n")

    # 如果有自定义DNS规则，也保存调试信息
    if custom_domain_dns:
        with open(os.path.join('dist', 'custom_domain_dns_debug.txt'), 'w', encoding='utf-8') as f:
            for domain, dns_list in sorted(custom_domain_dns.items()):
                f.write(f"{domain}: {', '.join(dns_list)}\n")

    # 输出总结日志
    logger.info("配置文件生成完成")
    logger.info(f"白名单模式：共 {len(cn_domains)} 个国内域名")
    logger.info(f"黑名单模式：共 {len(foreign_domains)} 个国外域名")
    logger.info(f"自定义域名DNS：共 {len(custom_domain_dns)} 个域名")

    # 额外统计自定义DNS规则覆盖的域名数量
    if custom_domain_dns:
        cn_overridden = len(cn_domains.intersection(set(custom_domain_dns.keys())))
        foreign_overridden = len(foreign_domains.intersection(set(custom_domain_dns.keys())))

        if cn_overridden > 0:
            logger.info(f"自定义DNS覆盖了 {cn_overridden} 个国内域名")
        if foreign_overridden > 0:
            logger.info(f"自定义DNS覆盖了 {foreign_overridden} 个国外域名")

if __name__ == "__main__":
    main()