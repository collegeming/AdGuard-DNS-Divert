#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
域名提取转换脚本
功能：从gn.txt文件中提取域名，转换为QuanX白名单格式
格式：host-suffix, 域名, DIRECT
"""

import re

def extract_domains_from_file(file_path):
    """从文件中提取域名"""
    domains = set()  # 使用集合去重
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                # 去除空白字符和注释
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                
                # 提取域名（简单匹配，可根据实际文件格式调整）
                # 匹配类似 example.com 或 www.example.com 的域名
                match = re.search(r'[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+', line)
                if match:
                    domain = match.group(0)
                    # 提取顶级域名和二级域名（如从 www.example.com 提取 example.com）
                    parts = domain.split('.')
                    if len(parts) >= 2:
                        suffix_domain = '.'.join(parts[-2:])
                        domains.add(suffix_domain)
    
    except FileNotFoundError:
        print(f"错误：文件 {file_path} 不存在")
    except Exception as e:
        print(f"处理文件时出错：{e}")
    
    return sorted(domains)

def generate_quanx_rules(domains):
    """生成QuanX白名单规则"""
    rules = []
    for domain in domains:
        rules.append(f'host-suffix, {domain}, DIRECT')
    return rules

def save_rules_to_file(rules, output_file):
    """将规则保存到文件"""
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            # 添加注释
            file.write("# QuanX 国内应用白名单规则\n")
            file.write("# 格式：host-suffix, 域名, DIRECT\n\n")
            
            # 写入规则
            for rule in rules:
                file.write(rule + "\n")
        print(f"规则已成功保存到 {output_file}")
    except Exception as e:
        print(f"保存文件时出错：{e}")

def main():
    input_file = "gn.txt"  # 输入文件名
    output_file = "quanx_whitelist.txt"  # 输出文件名
    
    print(f"正在从 {input_file} 提取域名...")
    domains = extract_domains_from_file(input_file)
    
    if domains:
        print(f"提取到 {len(domains)} 个域名，正在生成QuanX规则...")
        rules = generate_quanx_rules(domains)
        save_rules_to_file(rules, output_file)
    else:
        print("未提取到有效域名")

if __name__ == "__main__":
    main()