#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuard Home 分流配置生成脚本
新增功能：在保留单域名规则的基础上，新增多域名分组规则
生成文件：
- whitelist_mode.txt：原始白名单
- blacklist_mode.txt：原始黑名单
- gn.txt：分组白名单（国内域名分组）
- gw.txt：分组黑名单（国外域名分组）
"""

import os
import sys
import json
import logging
import datetime
from typing import Dict, List, Set

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import extract_domains

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('DNS_Config_Generator')

# 常量配置
GROUP_SIZE = 10  # 每组域名数量

def load_config() -> dict:
    """加载配置文件"""
    config_path = os.path.join('config', 'config.json')
    
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
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)
        logger.info(f"初始化默认配置文件: {config_path}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def process_sources(sources: List[str], custom_file: str = None) -> Set[str]:
    """处理域名源数据"""
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
    """读取自定义域名DNS配置"""
    custom_dns = {}

    if not os.path.exists(file_path):
        logger.info(f"自定义DNS文件不存在: {file_path}")
        return custom_dns

    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if ':' not in line:
                logger.warning(f"第 {line_num} 行格式错误: {line}")
                continue

            domain, dns_str = map(str.strip, line.split(':', 1))
            dns_servers = [s.strip() for s in dns_str.split(',') if s.strip()]
            
            if not extract_domains.is_valid_domain(domain) and domain not in ['cn', 'hk', 'mo', 'tw']:
                logger.warning(f"第 {line_num} 行域名无效: {domain}")
                continue

            custom_dns[domain] = dns_servers
    
    logger.info(f"加载自定义DNS规则: {len(custom_dns)} 条")
    return custom_dns

def generate_single_whitelist(cn_domains: Set[str], foreign_dns: List[str], cn_dns: List[str], custom_dns: Dict) -> str:
    """生成单域名白名单配置"""
    config = [
        "# AdGuard Home 白名单模式（单域名）",
        f"# 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# 默认DNS（国外）:",
        *foreign_dns,
        ""
    ]

    if custom_dns:
        config.extend([
            "# 自定义规则（优先级最高）",
            *[f"[/{k}/]{' '.join(v)}" for k, v in sorted(custom_dns.items())],
            ""
        ])

    filtered = cn_domains - set(custom_dns.keys())
    config.extend([
        "# 国内域名规则（单域名）",
        *[f"[/{d}/]{' '.join(cn_dns)}" for d in sorted(filtered)]
    ])
    
    return '\n'.join(config)

def generate_single_blacklist(foreign_domains: Set[str], cn_dns: List[str], foreign_dns: List[str], custom_dns: Dict) -> str:
    """生成单域名黑名单配置"""
    config = [
        "# AdGuard Home 黑名单模式（单域名）",
        f"# 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# 默认DNS（国内）:",
        *cn_dns,
        ""
    ]

    if custom_dns:
        config.extend([
            "# 自定义规则（优先级最高）",
            *[f"[/{k}/]{' '.join(v)}" for k, v in sorted(custom_dns.items())],
            ""
        ])

    filtered = foreign_domains - set(custom_dns.keys())
    config.extend([
        "# 国外域名规则（单域名）",
        *[f"[/{d}/]{' '.join(foreign_dns)}" for d in sorted(filtered)]
    ])
    
    return '\n'.join(config)

def generate_grouped_rules(domains: Set[str], dns: List[str]) -> List[str]:
    """生成分组规则"""
    sorted_domains = sorted(domains)
    return [
        f"[/{'/'.join(sorted_domains[i:i+GROUP_SIZE])}/]{' '.join(dns)}"
        for i in range(0, len(sorted_domains), GROUP_SIZE)
    ]

def generate_grouped_whitelist(cn_domains: Set[str], foreign_dns: List[str], cn_dns: List[str], custom_dns: Dict) -> str:
    """生成分组白名单配置"""
    config = [
        "# AdGuard Home 白名单模式（分组）",
        f"# 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# 默认DNS（国外）:",
        *foreign_dns,
        ""
    ]

    if custom_dns:
        config.extend([
            "# 自定义规则（优先级最高）",
            *[f"[/{k}/]{' '.join(v)}" for k, v in sorted(custom_dns.items())],
            ""
        ])

    filtered = cn_domains - set(custom_dns.keys())
    config.extend([
        "# 国内域名规则（分组）",
        *generate_grouped_rules(filtered, cn_dns)
    ])
    
    return '\n'.join(config)

def generate_grouped_blacklist(foreign_domains: Set[str], cn_dns: List[str], foreign_dns: List[str], custom_dns: Dict) -> str:
    """生成分组黑名单配置"""
    config = [
        "# AdGuard Home 黑名单模式（分组）",
        f"# 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# 默认DNS（国内）:",
        *cn_dns,
        ""
    ]

    if custom_dns:
        config.extend([
            "# 自定义规则（优先级最高）",
            *[f"[/{k}/]{' '.join(v)}" for k, v in sorted(custom_dns.items())],
            ""
        ])

    filtered = foreign_domains - set(custom_dns.keys())
    config.extend([
        "# 国外域名规则（分组）",
        *generate_grouped_rules(filtered, foreign_dns)
    ])
    
    return '\n'.join(config)

def main():
    """主函数"""
    # 初始化配置
    config = load_config()
    
    # 加载DNS配置
    cn_dns = extract_domains.read_dns_servers(
        os.path.join('config', 'cn_dns.txt'),
        default=["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
    )
    foreign_dns = extract_domains.read_dns_servers(
        os.path.join('config', 'foreign_dns.txt'),
        default=["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
    )
    
    # 加载自定义规则
    custom_dns = read_custom_domain_dns(os.path.join('config', 'custom_domain_dns.txt'))
    
    # 处理域名源
    cn_domains = process_sources(
        config['sources']['cn_domains'],
        os.path.join('config', 'custom_cn_domains.txt')
    )
    foreign_domains = process_sources(
        config['sources']['foreign_domains'],
        os.path.join('config', 'custom_foreign_domains.txt')
    )
    
    # 去重处理
    cn_domains = set(sorted(cn_domains))
    foreign_domains = set(sorted(foreign_domains))
    
    # 生成配置
    os.makedirs('dist', exist_ok=True)
    
    # 生成单域名规则
    with open(os.path.join('dist', 'whitelist_mode.txt'), 'w', encoding='utf-8') as f:
        content = generate_single_whitelist(cn_domains, foreign_dns, cn_dns, custom_dns)
        f.write(content)
    
    with open(os.path.join('dist', 'blacklist_mode.txt'), 'w', encoding='utf-8') as f:
        content = generate_single_blacklist(foreign_domains, cn_dns, foreign_dns, custom_dns)
        f.write(content)
    
    # 生成分组规则
    with open(os.path.join('dist', 'gn.txt'), 'w', encoding='utf-8') as f:
        content = generate_grouped_whitelist(cn_domains, foreign_dns, cn_dns, custom_dns)
        f.write(content)
    
    with open(os.path.join('dist', 'gw.txt'), 'w', encoding='utf-8') as f:
        content = generate_grouped_blacklist(foreign_domains, cn_dns, foreign_dns, custom_dns)
        f.write(content)
    
    # 输出统计信息
    logger.info(f"""
    生成结果统计：
    - 单域名白名单: whitelist_mode.txt ({len(cn_domains)} 域名)
    - 单域名黑名单: blacklist_mode.txt ({len(foreign_domains)} 域名)
    - 分组白名单: gn.txt ({len(cn_domains)} 域名 → {len(cn_domains)//GROUP_SIZE + 1} 组)
    - 分组黑名单: gw.txt ({len(foreign_domains)} 域名 → {len(foreign_domains)//GROUP_SIZE + 1} 组)
    自定义规则覆盖：
    - 国内域名: {len(cn_domains & set(custom_dns.keys()))}
    - 国外域名: {len(foreign_domains & set(custom_dns.keys()))}
    """)

if __name__ == "__main__":
    main()