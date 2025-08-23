#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
域名转换脚本（统一从dist目录读取国内外域名）
功能：
1. 从dist/cn_domains.txt提取域名，生成QuanX白名单（DIRECT）
2. 合并dist/foreign_domains.txt和config/custom_foreign_domains.txt的域名，生成QuanX规则（proxy）
格式：host-suffix, 域名, 策略
"""

import re
import os

def extract_domains(file_path, policy):
    """从文件提取域名并处理格式"""
    domains = set()
    full_path = os.path.join("dist", file_path)
    
    try:
        if not os.path.exists(full_path):
            print(f"警告：文件 {full_path} 不存在，跳过处理")
            return set()
        
        with open(full_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('#', ';')):
                    continue
                
                # 提取域名（支持带协议头或路径的情况）
                domain = re.sub(r'^https?://', '', line)  # 去除协议头
                domain = re.split(r'[/?#]', domain)[0]  # 去除路径和参数
                
                # 提取二级域名+顶级域名（如 example.com）
                parts = domain.split('.')
                if len(parts) >= 2:
                    suffix_domain = '.'.join(parts[-2:])
                    domains.add(suffix_domain)
    
    except Exception as e:
        print(f"处理文件时出错：{e}")
    return domains

def generate_quanx_rules(domains, policy):
    """生成QuanX规则"""
    return [f"host-suffix, {domain}, {policy}" for domain in sorted(domains)]

def save_rules(domains, policy, output_file):
    """保存规则到dist目录"""
    if not domains:
        print(f"警告：无有效域名，未生成{output_file}")
        return
    
    try:
        output_path = os.path.join("dist", output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# QuanX {policy.lower()}规则（自动生成）\n")
            f.write(f"# 格式：host-suffix, 域名, {policy}\n\n")
            f.write('\n'.join(generate_quanx_rules(domains, policy)))
        print(f"已保存{len(domains)}条规则到 {output_path}")
    except Exception as e:
        print(f"保存文件时出错：{e}")

def main():
    # 处理国内域名（生成DIRECT规则）
    cn_domains = extract_domains("cn_domains.txt", "DIRECT")
    save_rules(cn_domains, "DIRECT", "quanx_whitelist.txt")
    
    # 处理国外域名（合并两个文件并去重）
    foreign_domains = set()
    foreign_domains.update(extract_domains("foreign_domains.txt", "proxy"))
    custom_path = os.path.join("config", "custom_foreign_domains.txt")
    foreign_domains.update(extract_domains(custom_path, "proxy"))
    
    if foreign_domains:
        save_rules(foreign_domains, "proxy", "foreign_quanx_rules.txt")
    else:
        print("警告：国外域名合并后无有效数据，未生成规则文件")

if __name__ == "__main__":
    main()