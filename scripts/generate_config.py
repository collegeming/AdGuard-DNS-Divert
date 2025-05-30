#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置文件生成脚本
用于生成 AdGuard Home 的配置文件，包括白名单模式和黑名单模式

功能说明：
1. 加载配置文件（如果不存在则创建默认配置）；
2. 使用 extract_domains 模块下载并解析国内外域名源，同时支持自定义域名和自定义DNS规则；
3. 生成两个模式的配置文件：
   - 白名单模式：国内域名走国内DNS，其余走国外DNS
   - 黑名单模式：国外域名走国外DNS，其余走国内DNS
4. 输出文件包括：
   - gn.txt（原有白名单模式配置）
   - gw.txt（原有黑名单模式配置）
   - whitelist_mode.txt（新白名单模式配置）
   - blacklist_mode.txt（新黑名单模式配置）
   同时生成调试用的域名列表和自定义DNS规则文件。
"""

import os
import sys
import json
import logging
import datetime
from typing import Dict, List, Set
from collections import defaultdict

# 将当前脚本所在目录追加到模块搜索路径中，避免循环导入问题
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import extract_domains

# 配置日志输出
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("generate_config")

def load_config() -> dict:
    """加载配置文件，如果不存在则自动创建默认配置"""
    config_path = os.path.join("config", "config.json")
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
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logger.info(f"已创建默认配置文件 {config_path}")
    else:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    return config

def process_sources(sources: List[str], custom_file: str = None) -> Set[str]:
    """处理域名源列表，下载并提取域名，同时合并自定义域名文件中的域名"""
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
    读取自定义域名DNS配置，例如：
      domain1.com: dns1, dns2, dns3
      domain2.com: dns4
      # 注释行
    """
    custom_dns = {}
    if not os.path.exists(file_path):
        logger.info(f"自定义域名DNS文件不存在: {file_path}")
        return custom_dns
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                logger.warning(f"第 {line_num} 行格式错误，缺少冒号: {line}")
                continue
            parts = line.split(":", 1)
            domain = parts[0].strip()
            dns_servers = [dns.strip() for dns in parts[1].split(",") if dns.strip()]
            if not domain:
                logger.warning(f"第 {line_num} 行域名为空")
                continue
            if not dns_servers:
                logger.warning(f"第 {line_num} 行DNS服务器为空")
                continue
            if not extract_domains.is_valid_domain(domain) and domain not in ["cn","hk","mo","tw","jp","kr","sg"]:
                logger.warning(f"第 {line_num} 行域名格式无效: {domain}")
                continue
            custom_dns[domain] = dns_servers
            logger.info(f"添加自定义DNS规则: {domain} -> {dns_servers}")
    logger.info(f"从自定义DNS文件中读取了 {len(custom_dns)} 条规则")
    return custom_dns

def generate_whitelist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns=None) -> str:
    """
    生成白名单模式配置（国内域名走国内DNS，其余走国外DNS）
    """
    config_lines = []
    # 添加头部注释
    config_lines.append("# AdGuard Home DNS 分流配置 - 白名单模式")
    config_lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config_lines.append("# 白名单模式：国内域名走国内DNS，其他走国外DNS")
    if custom_domain_dns:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    # 添加默认上游DNS服务器（国外）
    config_lines.append("# 默认上游DNS服务器（国外）")
    for dns in foreign_dns:
        config_lines.append(dns)
    config_lines.append("")
    # 添加自定义域名DNS规则（优先级最高）
    if custom_domain_dns:
        config_lines.append("#" + "=" * 50)
        config_lines.append(f"# 自定义域名DNS规则（共 {len(custom_domain_dns)} 个域名）")
        config_lines.append("# 这些规则优先级最高，会覆盖下面的规则")
        config_lines.append("#" + "=" * 50)
        for domain, dns_list in sorted(custom_domain_dns.items()):
            dns_string = " ".join(dns_list)
            config_lines.append(f"[/{domain}/]{dns_string}")
        config_lines.append("")
    # 对国内域名排除自定义DNS的域名
    cn_domains_filtered = cn_domains - set(custom_domain_dns.keys()) if custom_domain_dns else cn_domains
    config_lines.append("#" + "=" * 50)
    config_lines.append(f"# 国内域名规则（共 {len(cn_domains_filtered)} 个域名）")
    if custom_domain_dns and len(cn_domains) != len(cn_domains_filtered):
        config_lines.append(f"# 已排除 {len(cn_domains) - len(cn_domains_filtered)} 个自定义DNS域名")
    config_lines.append("#" + "=" * 50)
    for domain in sorted(cn_domains_filtered):
        dns_list = " ".join(cn_dns)
        config_lines.append(f"[/{domain}/]{dns_list}")
    return "\n".join(config_lines)

def generate_blacklist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns=None) -> str:
    """
    生成黑名单模式配置（国外域名走国外DNS，其余走国内DNS）
    """
    config_lines = []
    # 添加头部注释
    config_lines.append("# AdGuard Home DNS 分流配置 - 黑名单模式")
    config_lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config_lines.append("# 黑名单模式：国外域名走国外DNS，其余走国内DNS")
    if custom_domain_dns:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    # 添加默认上游DNS服务器（国内）
    config_lines.append("# 默认上游DNS服务器（国内）")
    for dns in cn_dns:
        config_lines.append(dns)
    config_lines.append("")
    # 添加自定义域名DNS规则（优先级最高）
    if custom_domain_dns:
        config_lines.append("#" + "=" * 50)
        config_lines.append(f"# 自定义域名DNS规则（共 {len(custom_domain_dns)} 个域名）")
        config_lines.append("# 这些规则优先级最高，会覆盖下面的规则")
        config_lines.append("#" + "=" * 50)
        for domain, dns_list in sorted(custom_domain_dns.items()):
            dns_string = " ".join(dns_list)
            config_lines.append(f"[/{domain}/]{dns_string}")
        config_lines.append("")
    # 对国外域名排除自定义DNS的域名
    foreign_domains_filtered = foreign_domains - set(custom_domain_dns.keys()) if custom_domain_dns else foreign_domains
    config_lines.append("#" + "=" * 50)
    config_lines.append(f"# 国外域名规则（共 {len(foreign_domains_filtered)} 个域名）")
    if custom_domain_dns and len(foreign_domains) != len(foreign_domains_filtered):
        config_lines.append(f"# 已排除 {len(foreign_domains) - len(foreign_domains_filtered)} 个自定义DNS域名")
    config_lines.append("#" + "=" * 50)
    for domain in sorted(foreign_domains_filtered):
        dns_list = " ".join(foreign_dns)
        config_lines.append(f"[/{domain}/]{dns_list}")
    return "\n".join(config_lines)

def remove_duplicates_in_list(domains):
    """在单个列表内部去重，并返回唯一域名集合"""
    initial_count = len(domains)
    unique_domains = set(domains)
    if len(unique_domains) < initial_count:
        logger.info(f"从列表中移除了 {initial_count - len(unique_domains)} 个重复域名")
    return unique_domains

def main():
    """主函数"""
    # 加载配置
    config = load_config()
    # 设置默认DNS服务器
    default_cn_dns = ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
    default_foreign_dns = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
    cn_dns = extract_domains.read_dns_servers(os.path.join("config", "cn_dns.txt"), default_cn_dns)
    foreign_dns = extract_domains.read_dns_servers(os.path.join("config", "foreign_dns.txt"), default_foreign_dns)
    # 读取自定义域名DNS配置
    custom_domain_dns = read_custom_domain_dns(os.path.join("config", "custom_domain_dns.txt"))
    logger.info(f"使用国内DNS服务器: {cn_dns}")
    logger.info(f"使用国外DNS服务器: {foreign_dns}")
    logger.info(f"自定义域名DNS规则数: {len(custom_domain_dns)}")
    # 获取域名源
    cn_sources = config.get("sources", {}).get("cn_domains", [])
    foreign_sources = config.get("sources", {}).get("foreign_domains", [])
    logger.info("开始提取国内域名...")
    cn_domains = process_sources(cn_sources, os.path.join("config", "custom_cn_domains.txt"))
    logger.info("开始提取国外域名...")
    foreign_domains = process_sources(foreign_sources, os.path.join("config", "custom_foreign_domains.txt"))
    # 分别对国内与国外域名列表去重
    logger.info("对国内域名列表进行去重...")
    cn_domains = remove_duplicates_in_list(cn_domains)
    logger.info(f"去重后国内域名数量: {len(cn_domains)}")
    logger.info("对国外域名列表进行去重...")
    foreign_domains = remove_duplicates_in_list(foreign_domains)
    logger.info(f"去重后国外域名数量: {len(foreign_domains)}")
    # 生成白名单和黑名单配置
    logger.info("生成白名单模式配置文件...")
    whitelist_config = generate_whitelist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns)
    logger.info("生成黑名单模式配置文件...")
    blacklist_config = generate_blacklist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns)
    # 确保输出目录存在
    os.makedirs("dist", exist_ok=True)
    # 保留原有的 gn.txt 和 gw.txt 配置文件
    with open(os.path.join("dist", "gn.txt"), "w", encoding="utf-8") as f:
        f.write(whitelist_config)
    with open(os.path.join("dist", "gw.txt"), "w", encoding="utf-8") as f:
        f.write(blacklist_config)
    # 同时输出新的 whitelist_mode.txt 和 blacklist_mode.txt
    with open(os.path.join("dist", "whitelist_mode.txt"), "w", encoding="utf-8") as f:
        f.write(whitelist_config)
    with open(os.path.join("dist", "blacklist_mode.txt"), "w", encoding="utf-8") as f:
        f.write(blacklist_config)
    # 保存调试用的域名列表
    with open(os.path.join("dist", "cn_domains.txt"), "w", encoding="utf-8") as f:
        for domain in sorted(cn_domains):
            f.write(f"{domain}\n")
    with open(os.path.join("dist", "foreign_domains.txt"), "w", encoding="utf-8") as f:
        for domain in sorted(foreign_domains):
            f.write(f"{domain}\n")
    # 保存调试用的自定义域名DNS规则
    if custom_domain_dns:
        with open(os.path.join("dist", "custom_domain_dns_debug.txt"), "w", encoding="utf-8") as f:
            for domain, dns_list in sorted(custom_domain_dns.items()):
                f.write(f"{domain}: {', '.join(dns_list)}\n")
    logger.info("配置文件生成完成")
    logger.info(f"白名单模式：共 {len(cn_domains)} 个国内域名")
    logger.info(f"黑名单模式：共 {len(foreign_domains)} 个国外域名")
    logger.info(f"自定义域名DNS：共 {len(custom_domain_dns)} 个域名")
    # 统计自定义DNS规则覆盖情况
    if custom_domain_dns:
        cn_overridden = len(cn_domains.intersection(set(custom_domain_dns.keys())))
        foreign_overridden = len(foreign_domains.intersection(set(custom_domain_dns.keys())))
        if cn_overridden > 0:
            logger.info(f"自定义DNS覆盖了 {cn_overridden} 个国内域名")
        if foreign_overridden > 0:
            logger.info(f"自定义DNS覆盖了 {foreign_overridden} 个国外域名")

if __name__ == "__main__":
    main()