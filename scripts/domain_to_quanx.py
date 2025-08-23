#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
域名转换脚本（合并国外域名并去重）
功能：
1. 国内域名：dist/cn_domains.txt → DIRECT规则
2. 国外域名：合并dist/foreign_domains.txt和config/custom_foreign_domains.txt → proxy规则
"""

import re
import os

def extract_domains(file_path, policy):
    """提取域名并返回集合（自动去重）"""
    domains = set()
    full_path = os.path.join("dist" if "dist" in file_path else "", file_path)
    
    if not os.path.exists(full_path):
        print(f"[警告] 文件不存在: {full_path}")
        return domains
    
    with open(full_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            raw_line = line.strip()
            if not raw_line or raw_line.startswith(('#', ';')):
                continue
            
            # 提取域名核心逻辑（带调试日志）
            domain = re.sub(r'^https?://', '', raw_line)
            domain = re.split(r'[/?#]', domain)[0]
            parts = domain.split('.')
            
            if len(parts) >= 2:
                suffix_domain = '.'.join(parts[-2:])
                domains.add(suffix_domain)
                print(f"[调试] 提取成功: {suffix_domain} （原始行: {raw_line}）")
            else:
                print(f"[警告] 无效域名格式: {raw_line} （行号: {line_num}）")
    return domains

def generate_quanx_rules(domains, policy):
    """生成QuanX规则（排序后生成）"""
    if not domains:
        return []
    return [f"host-suffix, {domain}, {policy}" for domain in sorted(domains)]

def save_rules(domains, policy, output_file):
    """保存规则到文件"""
    if not domains:
        print(f"[警告] 无有效域名，未生成 {output_file}")
        return
    
    output_path = os.path.join("dist", output_file)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# QuanX {policy.lower()}规则（合并后共{len(domains)}条）\n")
        f.write(f"# 最后更新: {os.path.basename(__file__)} 自动生成\n\n")
        f.write('\n'.join(generate_quanx_rules(domains, policy)))
    print(f"[成功] 已保存 {len(domains)} 条规则到 {output_path}")

def main():
    print("===== 开始处理域名转换 =====")
    
    # 处理国内域名
    cn_domains = extract_domains("cn_domains.txt", "DIRECT")
    save_rules(cn_domains, "DIRECT", "quanx_whitelist.txt")
    
    # 合并国外域名（重点优化部分）
    foreign_domains = set()
    
    # 读取主国外域名文件
    foreign_main = extract_domains("dist/foreign_domains.txt", "proxy")
    foreign_domains.update(foreign_main)
    print(f"[统计] 主国外域名文件提取: {len(foreign_main)} 条")
    
    # 读取自定义国外域名文件
    custom_path = "config/custom_foreign_domains.txt"
    custom_domains = extract_domains(custom_path, "proxy")
    foreign_domains.update(custom_domains)
    print(f"[统计] 自定义域名文件提取: {len(custom_domains)} 条")
    
    # 去重后统计
    unique_count = len(foreign_domains)
    print(f"[统计] 合并后去重: {unique_count} 条（去重率: {(1 - unique_count / (len(foreign_main) + len(custom_domains))) * 100:.2f}%）")
    
    # 保存国外规则
    if foreign_domains:
        save_rules(foreign_domains, "proxy", "foreign_quanx_rules.txt")
    else:
        print("[警告] 国外域名合并后无有效数据")
    
    print("===== 处理完成 =====")

if __name__ == "__main__":
    main()