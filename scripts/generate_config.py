#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuard Home 分流配置生成脚本
新增功能：在保留单域名规则的基础上，新增多域名分组规则
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

def generate_grouped_rules(domains: Set[str], dns_servers: List[str]) -> List[str]:
    """生成分组规则（新增函数）"""
    sorted_domains = sorted(domains)
    grouped_rules = []
    
    for i in range(0, len(sorted_domains), GROUP_SIZE):
        group = sorted_domains[i:i+GROUP_SIZE]
        rule = f"[/{'/'.join(group)}/]{' '.join(dns_servers)}"
        grouped_rules.append(rule)
    
    logger.info(f"生成分组规则：共 {len(grouped_rules)} 组，每组最多 {GROUP_SIZE} 个域名")
    return grouped_rules

def generate_grouped_whitelist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns=None) -> str:
    """生成分组白名单配置（新增函数）"""
    config_lines = []
    
    # 头部信息
    config_lines.append("# AdGuard Home DNS 分流配置 - 白名单模式（分组）")
    config_lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config_lines.append("# 规则说明：国内域名分组走国内DNS，其他走国外DNS")
    if custom_domain_dns:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    
    # 默认DNS
    config_lines.append("# 默认上游DNS服务器（国外）")
    config_lines.extend(foreign_dns)
    config_lines.append("")
    
    # 自定义规则
    if custom_domain_dns:
        config_lines.append("#" + "="*50)
        config_lines.append("# 自定义域名DNS规则（优先级最高）")
        config_lines.extend([f"[/{k}/]{' '.join(v)}" for k, v in sorted(custom_domain_dns.items())])
        config_lines.append("")
    
    # 国内域名分组规则
    filtered_domains = cn_domains - set(custom_domain_dns.keys()) if custom_domain_dns else cn_domains
    config_lines.append("#" + "="*50)
    config_lines.append(f"# 国内域名分组规则（共 {len(filtered_domains)} 个域名）")
    config_lines.extend(generate_grouped_rules(filtered_domains, cn_dns))
    
    return '\n'.join(config_lines)

def generate_grouped_blacklist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns=None) -> str:
    """生成分组黑名单配置（新增函数）"""
    config_lines = []
    
    # 头部信息
    config_lines.append("# AdGuard Home DNS 分流配置 - 黑名单模式（分组）")
    config_lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config_lines.append("# 规则说明：国外域名分组走国外DNS，其他走国内DNS")
    if custom_domain_dns:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    
    # 默认DNS
    config_lines.append("# 默认上游DNS服务器（国内）")
    config_lines.extend(cn_dns)
    config_lines.append("")
    
    # 自定义规则
    if custom_domain_dns:
        config_lines.append("#" + "="*50)
        config_lines.append("# 自定义域名DNS规则（优先级最高）")
        config_lines.extend([f"[/{k}/]{' '.join(v)}" for k, v in sorted(custom_domain_dns.items())])
        config_lines.append("")
    
    # 国外域名分组规则
    filtered_domains = foreign_domains - set(custom_domain_dns.keys()) if custom_domain_dns else foreign_domains
    config_lines.append("#" + "="*50)
    config_lines.append(f"# 国外域名分组规则（共 {len(filtered_domains)} 个域名）")
    config_lines.extend(generate_grouped_rules(filtered_domains, foreign_dns))
    
    return '\n'.join(config_lines)

def main():
    """主函数"""
    # ...（保持原有main函数内容不变，只修改文件生成部分）...

    # 文件生成部分修改如下：
    # 保存原始单域名规则
    with open(os.path.join('dist', 'whitelist_mode.txt'), 'w') as f:
        f.write(whitelist_config)
    with open(os.path.join('dist', 'blacklist_mode.txt'), 'w') as f:
        f.write(blacklist_config)
    
    # 保存分组规则（新增部分）
    logger.info("生成分组白名单配置文件...")
    grouped_whitelist = generate_grouped_whitelist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns)
    with open(os.path.join('dist', 'gn.txt'), 'w') as f:
        f.write(grouped_whitelist)
    
    logger.info("生成分组黑名单配置文件...")
    grouped_blacklist = generate_grouped_blacklist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns)
    with open(os.path.join('dist', 'gw.txt'), 'w') as f:
        f.write(grouped_blacklist)

    # 更新日志输出
    logger.info("配置文件生成完成")
    logger.info(f"单域名规则：whitelist_mode.txt ({len(cn_domains)}), blacklist_mode.txt ({len(foreign_domains)})")
    logger.info(f"分组规则：gn.txt ({len(cn_domains)}), gw.txt ({len(foreign_domains)})")