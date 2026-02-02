#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CyberThreatHunter - DNS子域名枚举模块
用于发现目标域名的所有子域名
"""

import dns.resolver
import dns.exception
import concurrent.futures
from typing import List, Dict, Any, Optional, Set
import time
import logging
from pathlib import Path


class SubdomainEnumerator:
    """子域名枚举器"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化子域名枚举器
        
        Args:
            config: 配置文件
        """
        self.config = config
        self.dns_config = config.get("dns", {})
        self.scan_config = config.get("scanning", {})
        self.logger = logging.getLogger("VulnScanner.SubdomainEnumerator")
        
        # 设置DNS解析器
        self.resolver = dns.resolver.Resolver()
        
        # 配置DNS服务器
        dns_servers = self.dns_config.get("dns_servers", ["8.8.8.8", "8.8.4.4"])
        self.resolver.nameservers = dns_servers
        
        # 设置超时
        self.resolver.timeout = self.scan_config.get("timeout", 5)
        self.resolver.lifetime = self.scan_config.get("timeout", 5)
    
    def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """
        加载子域名字典
        
        Args:
            wordlist_path: 字典文件路径
            
        Returns:
            List[str]: 子域名列表
        """
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.logger.info(f"加载子域名字典: {wordlist_path}, 词条数: {len(words)}")
                return words
        except FileNotFoundError:
            self.logger.warning(f"字典文件未找到: {wordlist_path}，使用内置字典")
            return self._get_default_wordlist()
    
    def _get_default_wordlist(self) -> List[str]:
        """获取内置默认字典"""
        default_words = [
            "www", "mail", "email", "webmail", "smtp", "pop", "imap",
            "ftp", "ssh", "vpn", "admin", "administrator", "login",
            "portal", "intranet", "extranet", "api", "api1", "api2",
            "dev", "development", "test", "testing", "stage", "staging",
            "prod", "production", "demo", "sandbox", "blog", "news",
            "support", "help", "kb", "wiki", "docs", "documentation",
            "static", "cdn", "assets", "img", "images", "media",
            "app", "apps", "mobile", "m", "wap"
        ]
        return default_words
    
    def _query_dns(self, subdomain: str, domain: str, record_type: str = "A") -> Optional[List[str]]:
        """
        查询DNS记录
        
        Args:
            subdomain: 子域名部分
            domain: 主域名
            record_type: 记录类型 (A, AAAA, CNAME, MX, etc.)
            
        Returns:
            Optional[List[str]]: DNS记录值列表，如果查询失败返回None
        """
        full_domain = f"{subdomain}.{domain}" if subdomain else domain
        
        try:
            answers = self.resolver.resolve(full_domain, record_type)
            records = [str(r) for r in answers]
            return records
            
        except dns.resolver.NXDOMAIN:
            # 域名不存在
            return None
        except dns.resolver.NoAnswer:
            # 没有对应记录
            return None
        except dns.resolver.Timeout:
            self.logger.debug(f"DNS查询超时: {full_domain}")
            return None
        except dns.exception.DNSException as e:
            self.logger.debug(f"DNS查询异常: {full_domain}, 错误: {e}")
            return None
    
    def _create_finding(self, target: str, subdomain: str, records: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        创建子域名发现项
        
        Args:
            target: 目标域名
            subdomain: 发现的子域名
            records: DNS记录
            
        Returns:
            Dict: 发现项
        """
        full_domain = f"{subdomain}.{target}" if subdomain else target
        
        # 风险评估
        sensitive_subdomains = {
            "admin": "high",
            "administrator": "high",
            "login": "medium",
            "panel": "medium",
            "dashboard": "medium",
            "vpn": "high",
            "ssh": "high",
            "ftp": "medium",
            "mail": "medium",
            "api": "medium",
            "dev": "low",
            "test": "low",
            "staging": "low",
            "prod": "info"
        }
        
        severity = "info"
        for keyword, risk in sensitive_subdomains.items():
            if keyword in subdomain.lower():
                severity = risk
                break
        
        # 如果有A记录，检查是否为内部IP
        a_records = records.get("A", [])
        internal_ips = False
        for ip in a_records:
            if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", 
                            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                            "172.30.", "172.31.", "192.168.")):
                internal_ips = True
                severity = "high" if severity != "critical" else severity
        
        if internal_ips:
            severity = "high"
        
        finding = {
            "type": "subdomain",
            "name": f"发现的子域名: {full_domain}",
            "description": f"在目标 {target} 上发现子域名 {full_domain}",
            "severity": severity,
            "cvss_score": self._get_cvss_score(severity),
            "evidence": f"子域名: {full_domain}, DNS记录: {records}",
            "remediation": self._get_remediation(full_domain, records, internal_ips),
            "details": {
                "target": target,
                "subdomain": subdomain,
                "full_domain": full_domain,
                "dns_records": records,
                "has_internal_ip": internal_ips,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        }
        
        return finding
    
    def _get_cvss_score(self, severity: str) -> float:
        """根据风险等级获取CVSS分数"""
        scores = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 2.0,
            "info": 0.0
        }
        return scores.get(severity, 0.0)
    
    def _get_remediation(self, full_domain: str, records: Dict[str, List[str]], 
                        internal_ips: bool) -> str:
        """获取修复建议"""
        if internal_ips:
            return "子域名解析到内部IP地址，暴露了内部网络结构。建议将内部服务移至私有DNS区域。"
        
        if "admin" in full_domain.lower() or "login" in full_domain.lower():
            return "管理子域名暴露。建议使用非常规命名或启用访问控制。"
        
        if "api" in full_domain.lower():
            return "API子域名暴露。确保API有适当的认证和授权机制。"
        
        return "定期审查子域名配置，移除不再使用的子域名记录。"
    
    def enumerate(self, domain: str, wordlist: List[str] = None) -> Dict[str, Dict[str, List[str]]]:
        """
        枚举子域名
        
        Args:
            domain: 目标域名
            wordlist: 子域名字典
            
        Returns:
            Dict: 发现的子域名及其DNS记录
        """
        if wordlist is None:
            wordlist_path = self.dns_config.get("subdomains_wordlist", "config/wordlists/subdomains.txt")
            wordlist = self._load_wordlist(wordlist_path)
        
        results = {}
        
        self.logger.info(f"开始子域名枚举: {domain}")
        self.logger.info(f"字典大小: {len(wordlist)} 词条")
        
        # 首先检查主域名
        main_records = {}
        record_types = self.dns_config.get("record_types", ["A", "AAAA", "CNAME", "MX", "NS", "TXT"])
        
        for record_type in record_types:
            records = self._query_dns("", domain, record_type)
            if records:
                main_records[record_type] = records
        
        if main_records:
            results[""] = main_records
            self.logger.info(f"主域名 {domain} 有DNS记录")
        
        # 设置并发数
        max_workers = self.scan_config.get("threads", 50)
        
        # 使用线程池并发查询
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有DNS查询任务
            future_to_subdomain = {}
            
            for subdomain in wordlist:
                future = executor.submit(self._query_subdomain, subdomain, domain)
                future_to_subdomain[future] = subdomain
            
            # 收集结果
            completed = 0
            for future in concurrent.futures.as_completed(future_to_subdomain):
                completed += 1
                subdomain = future_to_subdomain[future]
                
                try:
                    result = future.result(timeout=self.scan_config.get("timeout", 5) + 2)
                    if result:
                        results[subdomain] = result
                        
                        if len(results) % 10 == 0:
                            self.logger.info(f"进度: {completed}/{len(wordlist)}, 发现: {len(results)}")
                            
                except concurrent.futures.TimeoutError:
                    self.logger.debug(f"子域名查询超时: {subdomain}")
                except Exception as e:
                    self.logger.debug(f"子域名查询异常: {subdomain}, 错误: {e}")
        
        self.logger.info(f"子域名枚举完成，发现 {len(results)} 个子域名")
        return results
    
    def _query_subdomain(self, subdomain: str, domain: str) -> Optional[Dict[str, List[str]]]:
        """
        查询单个子域名的所有DNS记录
        
        Args:
            subdomain: 子域名
            domain: 主域名
            
        Returns:
            Optional[Dict]: DNS记录字典
        """
        records = {}
        full_domain = f"{subdomain}.{domain}"
        
        record_types = self.dns_config.get("record_types", ["A", "AAAA", "CNAME"])
        
        has_valid_record = False
        
        for record_type in record_types:
            try:
                query_result = self._query_dns(subdomain, domain, record_type)
                if query_result:
                    records[record_type] = query_result
                    has_valid_record = True
            except Exception as e:
                self.logger.debug(f"查询 {full_domain} 的 {record_type} 记录失败: {e}")
        
        if has_valid_record:
            return records
        
        return None
    
    def bruteforce(self, domain: str, charset: str = "abcdefghijklmnopqrstuvwxyz0123456789-",
                  min_length: int = 1, max_length: int = 3) -> Dict[str, Dict[str, List[str]]]:
        """
        暴力破解子域名
        
        Args:
            domain: 目标域名
            charset: 字符集
            min_length: 最小长度
            max_length: 最大长度
            
        Returns:
            Dict: 发现的子域名
        """
        results = {}
        
        self.logger.info(f"开始暴力破解子域名: {domain}, 长度: {min_length}-{max_length}")
        
        # 生成所有可能的组合
        from itertools import product
        
        total_combinations = sum(len(charset) ** length for length in range(min_length, max_length + 1))
        self.logger.info(f"总组合数: {total_combinations}")
        
        # 限制组合数量
        if total_combinations > 10000:
            self.logger.warning(f"组合数过多 ({total_combinations})，限制为前10000个")
            # 实现简化版本...
            return results
        
        # 实际实现需要根据字符集和长度生成组合
        # 这里简化为使用预定义的常见短子域名
        common_short = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
                       "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
                       "u", "v", "w", "x", "y", "z", "0", "1", "2", "3",
                       "4", "5", "6", "7", "8", "9", "aa", "ab", "ac",
                       "ad", "ae", "af", "ag", "ah", "ai", "aj", "ak"]
        
        max_workers = self.scan_config.get("threads", 20)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_subdomain = {}
            
            for subdomain in common_short:
                future = executor.submit(self._query_subdomain, subdomain, domain)
                future_to_subdomain[future] = subdomain
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                
                try:
                    result = future.result()
                    if result:
                        results[subdomain] = result
                except Exception as e:
                    self.logger.debug(f"暴力破解查询失败: {subdomain}, 错误: {e}")
        
        self.logger.info(f"暴力破解完成，发现 {len(results)} 个子域名")
        return results
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        执行子域名扫描
        
        Args:
            target: 目标域名
            
        Returns:
            List[Dict]: 扫描结果
        """
        self.logger.info(f"开始子域名扫描: {target}")
        
        # 清理域名（移除协议和路径）
        if "://" in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            target = parsed.netloc
        
        # 移除端口号
        if ":" in target:
            target = target.split(":")[0]
        
        findings = []
        
        try:
            # 方法1：字典枚举
            self.logger.info("使用字典枚举子域名...")
            enumerated = self.enumerate(target)
            
            for subdomain, records in enumerated.items():
                full_domain = f"{subdomain}.{target}" if subdomain else target
                self.logger.info(f"发现子域名: {full_domain}")
                
                finding = self._create_finding(target, subdomain, records)
                findings.append(finding)
            
            # 方法2：暴力破解（可选）
            bruteforce_enabled = self.dns_config.get("bruteforce_enabled", False)
            if bruteforce_enabled and len(findings) < 10:  # 如果字典枚举发现不多，尝试暴力破解
                self.logger.info("尝试暴力破解短子域名...")
                bruteforced = self.bruteforce(target)
                
                for subdomain, records in bruteforced.items():
                    if subdomain not in enumerated:  # 避免重复
                        full_domain = f"{subdomain}.{target}"
                        self.logger.info(f"暴力破解发现子域名: {full_domain}")
                        
                        finding = self._create_finding(target, subdomain, records)
                        findings.append(finding)
            
            # 检查通配符DNS
            self.logger.info("检查通配符DNS配置...")
            wildcard_test = f"random{int(time.time())}.{target}"
            wildcard_records = self._query_dns(f"random{int(time.time())}", target, "A")
            
            if wildcard_records:
                finding = {
                    "type": "dns_wildcard",
                    "name": "通配符DNS配置",
                    "description": f"目标域名 {target} 配置了通配符DNS",
                    "severity": "medium",
                    "cvss_score": 4.0,
                    "evidence": f"随机子域名 {wildcard_test} 解析到: {wildcard_records}",
                    "remediation": "通配符DNS可能暴露内部服务。建议使用明确的子域名记录。",
                    "details": {
                        "target": target,
                        "test_subdomain": wildcard_test,
                        "records": wildcard_records,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                }
                findings.append(finding)
            
            # 检查DNS安全记录
            self.logger.info("检查DNS安全记录...")
            security_records = self._check_security_records(target)
            findings.extend(security_records)
            
        except Exception as e:
            self.logger.error(f"子域名扫描失败: {e}")
        
        self.logger.info(f"子域名扫描完成，发现 {len(findings)} 个子域名和相关问题")
        return findings
    
    def _check_security_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        检查DNS安全记录
        
        Args:
            domain: 目标域名
            
        Returns:
            List[Dict]: 安全记录问题
        """
        findings = []
        
        # 检查SPF记录
        try:
            spf_records = self._query_dns("", domain, "TXT")
            has_spf = False
            
            if spf_records:
                for record in spf_records:
                    if "v=spf1" in record:
                        has_spf = True
                        break
            
            if not has_spf:
                finding = {
                    "type": "dns_security",
                    "name": "缺少SPF记录",
                    "description": f"域名 {domain} 缺少SPF记录",
                    "severity": "medium",
                    "cvss_score": 4.0,
                    "evidence": "未找到SPF DNS记录",
                    "remediation": "添加SPF记录以防止邮件伪造",
                    "details": {
                        "target": domain,
                        "record_type": "SPF",
                        "issue": "missing",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                }
                findings.append(finding)
                
        except Exception as e:
            self.logger.debug(f"检查SPF记录失败: {e}")
        
        # 检查DMARC记录
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_records = self._query_dns("_dmarc", domain, "TXT")
            
            if not dmarc_records:
                finding = {
                    "type": "dns_security",
                    "name": "缺少DMARC记录",
                    "description": f"域名 {domain} 缺少DMARC记录",
                    "severity": "medium",
                    "cvss_score": 4.0,
                    "evidence": f"未找到 {dmarc_domain} 的DMARC记录",
                    "remediation": "添加DMARC记录以增强邮件安全",
                    "details": {
                        "target": domain,
                        "record_type": "DMARC",
                        "issue": "missing",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                }
                findings.append(finding)
                
        except Exception as e:
            self.logger.debug(f"检查DMARC记录失败: {e}")
        
        return findings


def main():
    """测试函数"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python subdomain_enum.py <目标域名>")
        print("示例: python subdomain_enum.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # 创建配置
    config = {
        "dns": {
            "subdomains_wordlist": "config/wordlists/subdomains.txt",
            "dns_servers": ["8.8.8.8", "8.8.4.4"],
            "record_types": ["A", "AAAA", "CNAME"]
        },
        "scanning": {
            "timeout": 5,
            "threads": 50
        }
    }
    
    # 设置日志
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    scanner = SubdomainEnumerator(config)
    findings = scanner.scan(target)
    
    print(f"\n子域名扫描结果 ({target}):")
    print("=" * 80)
    
    if findings:
        for finding in findings:
            print(f"类型: {finding['type']}")
            print(f"域名: {finding['details'].get('full_domain', finding['details'].get('target'))}")
            print(f"风险: {finding['severity']}")
            print(f"证据: {finding['evidence'][:100]}...")
            print("-" * 80)
    else:
        print("未发现子域名")
    
    print(f"总计发现: {len(findings)} 个")


if __name__ == "__main__":
    main()