#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ...（前略，与原脚本一致，省略无关部分）...

def generate_whitelist_config_single(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns=None):
    config_lines = []
    config_lines.append("# AdGuard Home DNS 分流配置 - 白名单模式（逐条规则）")
    config_lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config_lines.append("# 白名单模式：命中国内域名走国内DNS，其他走国外DNS")
    if custom_domain_dns:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    config_lines.append("# 默认上游DNS服务器（国外）")
    for dns in foreign_dns:
        config_lines.append(dns)
    config_lines.append("")
    if custom_domain_dns:
        config_lines.append("#" + "="*50)
        config_lines.append(f"# 自定义域名DNS规则（共 {len(custom_domain_dns)} 个域名）")
        config_lines.append("# 这些规则优先级最高，会覆盖下面的国内规则")
        config_lines.append("#" + "="*50)
        for domain, dns_list in sorted(custom_domain_dns.items()):
            config_lines.append(f"[/{domain}/]{' '.join(dns_list)}")
        config_lines.append("")
    cn_domains_filtered = cn_domains - set(custom_domain_dns.keys()) if custom_domain_dns else cn_domains
    config_lines.append("#" + "="*50)
    config_lines.append(f"# 国内域名规则（共 {len(cn_domains_filtered)} 个域名，逐条规则）")
    if custom_domain_dns and len(cn_domains) != len(cn_domains_filtered):
        config_lines.append(f"# 已排除 {len(cn_domains) - len(cn_domains_filtered)} 个自定义DNS域名")
    config_lines.append("#" + "="*50)
    for domain in sorted(cn_domains_filtered):
        config_lines.append(f"[/{domain}/]{' '.join(cn_dns)}")
    return '\n'.join(config_lines)

def generate_blacklist_config_single(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns=None):
    config_lines = []
    config_lines.append("# AdGuard Home DNS 分流配置 - 黑名单模式（逐条规则）")
    config_lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config_lines.append("# 黑名单模式：命中国外域名走国外DNS，其他走国内DNS")
    if custom_domain_dns:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    config_lines.append("# 默认上游DNS服务器（国内）")
    for dns in cn_dns:
        config_lines.append(dns)
    config_lines.append("")
    if custom_domain_dns:
        config_lines.append("#" + "="*50)
        config_lines.append(f"# 自定义域名DNS规则（共 {len(custom_domain_dns)} 个域名）")
        config_lines.append("# 这些规则优先级最高，会覆盖下面的国外规则")
        config_lines.append("#" + "="*50)
        for domain, dns_list in sorted(custom_domain_dns.items()):
            config_lines.append(f"[/{domain}/]{' '.join(dns_list)}")
        config_lines.append("")
    foreign_domains_filtered = foreign_domains - set(custom_domain_dns.keys()) if custom_domain_dns else foreign_domains
    config_lines.append("#" + "="*50)
    config_lines.append(f"# 国外域名规则（共 {len(foreign_domains_filtered)} 个域名，逐条规则）")
    if custom_domain_dns and len(foreign_domains) != len(foreign_domains_filtered):
        config_lines.append(f"# 已排除 {len(foreign_domains) - len(foreign_domains_filtered)} 个自定义DNS域名")
    config_lines.append("#" + "="*50)
    for domain in sorted(foreign_domains_filtered):
        config_lines.append(f"[/{domain}/]{' '.join(foreign_dns)}")
    return '\n'.join(config_lines)

# ...（grouped版的 generate_whitelist_config_grouped 和 generate_blacklist_config_grouped 保持原样）...

def main():
    # ...（前面部分不变）...

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

    # 生成四种分流文件
    logger.info("生成白名单模式配置文件（逐条规则）...")
    whitelist_config_single = generate_whitelist_config_single(
        cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns
    )
    logger.info("生成白名单模式配置文件（合并规则）...")
    whitelist_config_grouped = generate_whitelist_config_grouped(
        cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns
    )
    logger.info("生成黑名单模式配置文件（逐条规则）...")
    blacklist_config_single = generate_blacklist_config_single(
        cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns
    )
    logger.info("生成黑名单模式配置文件（合并规则）...")
    blacklist_config_grouped = generate_blacklist_config_grouped(
        cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns
    )

    os.makedirs('dist', exist_ok=True)
    # 保存文件
    with open(os.path.join('dist', 'gn.txt'), 'w', encoding='utf-8') as f:
        f.write(whitelist_config_single)
    with open(os.path.join('dist', 'gn_grouped.txt'), 'w', encoding='utf-8') as f:
        f.write(whitelist_config_grouped)
    with open(os.path.join('dist', 'gw.txt'), 'w', encoding='utf-8') as f:
        f.write(blacklist_config_single)
    with open(os.path.join('dist', 'gw_grouped.txt'), 'w', encoding='utf-8') as f:
        f.write(blacklist_config_grouped)

    # ...（后面调试文件保存部分不变）...

if __name__ == "__main__":
    main()
