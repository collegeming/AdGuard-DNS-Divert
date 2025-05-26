#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuard Home 分流配置生成脚本

主要功能：
1. 加载或创建基本配置文件（config/config.json）
2. 下载并解析远程域名规则列表，同时支持自定义域名文件（custom_cn_domains.txt, custom_foreign_domains.txt）
3. 读取自定义 DNS 规则（格式: domain: dns1, dns2, ...）
4. 根据提取的数据生成两种模式的配置：
   - 单域名规则（白名单：国内域名走国内DNS，其余走国外DNS；黑名单：国外域名走国外DNS，其余走国内DNS）
   - 分流规则：将所有域名按升序排序后用 "/" 连接，构造单行多DNS分流规则
5. 生成的文件保存在 dist 目录下：
   - whitelist_mode.txt：单域名白名单配置
   - blacklist_mode.txt：单域名黑名单配置
   - gn.txt：分流白名单规则（所有国内域名连在一起，用 "/" 分隔，后跟多个DNS）
   - gw.txt：分流黑名单规则（所有国外域名连在一起，用 "/" 分隔，后跟多个DNS）
   - 其它调试文件（域名列表、自定义 DNS 规则）也将保存到 dist 目录中
"""

import os
import sys
import json
import logging
import datetime
from typing import Dict, List, Set

# 避免循环导入，将当前脚本所在目录添加到 sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import extract_domains

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("DNS_Config_Generator")

def load_config() -> dict:
    """加载配置文件，如果不存在则创建默认配置"""
    config_path = os.path.join("config", "config.json")
    default_config = {
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
    if not os.path.exists(config_path):
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)
        logger.info(f"初始化默认配置文件: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def process_sources(sources: List[str], custom_file: str = None) -> Set[str]:
    """处理域名源数据，下载并合并各来源提取的域名"""
    domains = set()
    for source in sources:
        if content := extract_domains.download_file(source):
            extracted = extract_domains.extract_domains_from_file(content, source)
            logger.info(f"从 {source} 提取域名: {len(extracted)} 个")
            domains.update(extracted)
    if custom_file and os.path.exists(custom_file):
        custom_domains = extract_domains.read_custom_domains(custom_file)
        logger.info(f"加载自定义域名: {len(custom_domains)} 个")
        domains.update(custom_domains)
    return domains

def read_custom_domain_dns(file_path: str) -> Dict[str, List[str]]:
    """读取自定义域名 DNS 配置，格式如下：
       domain1.com: dns1, dns2, dns3
       domain2.com: dns4
       注释行将被忽略
    """
    custom_dns = {}
    if not os.path.exists(file_path):
        logger.info(f"自定义 DNS 文件不存在: {file_path}")
        return custom_dns
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                logger.warning(f"第 {line_num} 行格式错误: {line}")
                continue
            domain, dns_str = map(str.strip, line.split(":", 1))
            dns_servers = [s.strip() for s in dns_str.split(",") if s.strip()]
            # 只允许部分常见 TLD 的简写：cn, hk, mo, tw
            if not extract_domains.is_valid_domain(domain) and domain not in ["cn", "hk", "mo", "tw"]:
                logger.warning(f"第 {line_num} 行域名无效: {domain}")
                continue
            custom_dns[domain] = dns_servers
            logger.info(f"添加自定义 DNS 规则: {domain} -> {dns_servers}")
    logger.info(f"加载自定义 DNS 规则: {len(custom_dns)} 条")
    return custom_dns

def generate_single_whitelist(cn_domains: Set[str], foreign_dns: List[str],
                              cn_dns: List[str], custom_dns: Dict) -> str:
    """生成单域名白名单配置：
       默认使用国外 DNS，上层添加自定义规则，其余国内域名使用国内 DNS
    """
    config = [
        "# AdGuard Home 白名单模式（单域名）",
        f"# 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# 默认上游 DNS（国外）:",
        *foreign_dns,
        ""
    ]
    if custom_dns:
        config.extend([
            "# 自定义规则（优先级最高）",
            *[f"[/{k}/]{' '.join(v)}" for k, v in sorted(custom_dns.items())],
            ""
        ])
    filtered = cn_domains - set(custom_dns.keys()) if custom_dns else cn_domains
    config.extend([
        "# 国内域名规则（单域名）",
        *[f"[/{d}/]{' '.join(cn_dns)}" for d in sorted(filtered)]
    ])
    return "\n".join(config)

def generate_single_blacklist(foreign_domains: Set[str], cn_dns: List[str],
                              foreign_dns: List[str], custom_dns: Dict) -> str:
    """生成单域名黑名单配置：
       默认使用国内 DNS，上层添加自定义规则，其余国外域名使用国外 DNS
    """
    config = [
        "# AdGuard Home 黑名单模式（单域名）",
        f"# 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# 默认上游 DNS（国内）:",
        *cn_dns,
        ""
    ]
    if custom_dns:
        config.extend([
            "# 自定义规则（优先级最高）",
            *[f"[/{k}/]{' '.join(v)}" for k, v in sorted(custom_dns.items())],
            ""
        ])
    filtered = foreign_domains - set(custom_dns.keys()) if custom_dns else foreign_domains
    config.extend([
        "# 国外域名规则（单域名）",
        *[f"[/{d}/]{' '.join(foreign_dns)}" for d in sorted(filtered)]
    ])
    return "\n".join(config)

def generate_single_line_rule(domains: Set[str], dns: List[str]) -> str:
    """
    生成单行分流规则：
    将所有域名按升序排序后用 "/" 连接，然后构造规则格式：
    [/{域名1/域名2/.../}]{DNS服务器}
    """
    sorted_domains = sorted(domains)
    rule = f"[/{'/'.join(sorted_domains)}/]{' '.join(dns)}"
    return rule

def main():
    """主函数：加载配置、提取域名、生成配置文件和分流规则"""
    config = load_config()

    # 加载 DNS 服务器配置
    cn_dns = extract_domains.read_dns_servers(
        os.path.join("config", "cn_dns.txt"),
        default_servers=["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
    )
    foreign_dns = extract_domains.read_dns_servers(
        os.path.join("config", "foreign_dns.txt"),
        default_servers=["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
    )

    # 读取自定义 DNS 规则
    custom_dns = read_custom_domain_dns(os.path.join("config", "custom_domain_dns.txt"))
    logger.info(f"使用国内DNS服务器: {cn_dns}")
    logger.info(f"使用国外DNS服务器: {foreign_dns}")
    logger.info(f"自定义域名DNS规则数: {len(custom_dns)}")

    # 处理域名来源
    cn_sources = config.get("sources", {}).get("cn_domains", [])
    foreign_sources = config.get("sources", {}).get("foreign_domains", [])
    cn_domains = process_sources(cn_sources, os.path.join("config", "custom_cn_domains.txt"))
    foreign_domains = process_sources(foreign_sources, os.path.join("config", "custom_foreign_domains.txt"))

    # 确保域名唯一且有序
    cn_domains = set(sorted(cn_domains))
    foreign_domains = set(sorted(foreign_domains))

    # 确保输出目录存在
    os.makedirs("dist", exist_ok=True)

    # 生成单域名规则配置文件
    with open(os.path.join("dist", "whitelist_mode.txt"), "w", encoding="utf-8") as f:
        f.write(generate_single_whitelist(cn_domains, foreign_dns, cn_dns, custom_dns))
    with open(os.path.join("dist", "blacklist_mode.txt"), "w", encoding="utf-8") as f:
        f.write(generate_single_blacklist(foreign_domains, cn_dns, foreign_dns, custom_dns))

    # 生成分流规则配置文件（所有域名连在一起，用 "/" 分隔，多 DNS 分流规则）
    with open(os.path.join("dist", "gn.txt"), "w", encoding="utf-8") as f:
        f.write(generate_single_line_rule(cn_domains, cn_dns))
    with open(os.path.join("dist", "gw.txt"), "w", encoding="utf-8") as f:
        f.write(generate_single_line_rule(foreign_domains, foreign_dns))

    # 保存调试用的域名列表及自定义 DNS 信息
    with open(os.path.join("dist", "cn_domains.txt"), "w", encoding="utf-8") as f:
        for d in sorted(cn_domains):
            f.write(f"{d}\n")
    with open(os.path.join("dist", "foreign_domains.txt"), "w", encoding="utf-8") as f:
        for d in sorted(foreign_domains):
            f.write(f"{d}\n")
    if custom_dns:
        with open(os.path.join("dist", "custom_domain_dns_debug.txt"), "w", encoding="utf-8") as f:
            for domain, dns_list in sorted(custom_dns.items()):
                f.write(f"{domain}: {', '.join(dns_list)}\n")

    # 输出统计信息
    logger.info(f"""
生成结果统计:
- 单域名白名单: whitelist_mode.txt ({len(cn_domains)} 域名)
- 单域名黑名单: blacklist_mode.txt ({len(foreign_domains)} 域名)
- 分流白名单 (gn.txt): {len(cn_domains)} 域名
- 分流黑名单 (gw.txt): {len(foreign_domains)} 域名
自定义规则覆盖:
- 国内域名: {len(cn_domains & set(custom_dns.keys())) if custom_dns else 0}
- 国外域名: {len(foreign_domains & set(custom_dns.keys())) if custom_dns else 0}
    """)

if __name__ == "__main__":
    main()