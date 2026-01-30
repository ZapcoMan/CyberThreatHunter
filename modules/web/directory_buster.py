#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
目录爆破模块
用于发现Web应用中的隐藏目录和文件
"""

import requests
import concurrent.futures
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
import time
import logging
from pathlib import Path


class DirectoryBuster:
    """目录爆破扫描器"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化目录爆破器
        
        Args:
            config: 配置文件
        """
        self.config = config
        self.web_config = config.get("web", {})
        self.scan_config = config.get("scanning", {})
        self.logger = logging.getLogger("VulnScanner.DirectoryBuster")
        
        # 会话设置
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.scan_config.get("user_agent", "DirectoryBuster/1.0")
        })
        
        # 设置超时
        self.timeout = self.scan_config.get("timeout", 10)
        
        # 代理设置
        proxy = self.scan_config.get("proxy")
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
    
    def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """
        加载字典文件
        
        Args:
            wordlist_path: 字典文件路径
            
        Returns:
            List[str]: 字典列表
        """
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.logger.info(f"加载字典文件: {wordlist_path}, 词条数: {len(words)}")
                return words
        except FileNotFoundError:
            self.logger.warning(f"字典文件未找到: {wordlist_path}，使用内置字典")
            return self._get_default_wordlist()
    
    def _get_default_wordlist(self) -> List[str]:
        """获取内置默认字典"""
        default_words = [
            "admin", "administrator", "login", "panel", "dashboard",
            "config", "configuration", "backup", "backups", "bak",
            "old", "archive", "test", "testing", "dev", "development",
            "api", "v1", "v2", "rest", "graphql", "swagger",
            ".git", ".env", ".htaccess", "robots.txt", "sitemap.xml",
            "crossdomain.xml", "phpinfo.php", "info.php", "test.php"
        ]
        return default_words
    
    def _check_url(self, base_url: str, path: str) -> Optional[Dict[str, Any]]:
        """
        检查单个URL
        
        Args:
            base_url: 基础URL
            path: 要检查的路径
            
        Returns:
            Optional[Dict]: 如果找到则返回信息，否则返回None
        """
        url = urljoin(base_url, path)
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False  # 不自动重定向
            )
            
            status_code = response.status_code
            
            # 检查有效的响应状态码
            if status_code in [200, 301, 302, 303, 307, 308, 403, 401]:
                content_length = len(response.content)
                
                result = {
                    "url": url,
                    "status_code": status_code,
                    "content_length": content_length,
                    "headers": dict(response.headers),
                    "redirect_location": response.headers.get('Location', '') if status_code in [301, 302, 303, 307, 308] else None
                }
                
                return result
            
        except requests.exceptions.Timeout:
            self.logger.debug(f"请求超时: {url}")
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"连接错误: {url}")
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"请求异常: {url}, 错误: {e}")
        
        return None
    
    def _create_finding(self, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        创建目录发现项
        
        Args:
            target: 目标URL
            result: 检查结果
            
        Returns:
            Dict: 发现项
        """
        url = result["url"]
        status_code = result["status_code"]
        content_length = result["content_length"]
        
        # 风险评估
        sensitive_paths = {
            "admin": "high",
            "administrator": "high",
            "login": "medium",
            "panel": "medium",
            "dashboard": "medium",
            "config": "critical",
            "configuration": "critical",
            ".git": "critical",
            ".env": "critical",
            ".htaccess": "high",
            "backup": "high",
            "phpinfo.php": "high",
            "info.php": "high"
        }
        
        # 根据路径确定风险等级
        severity = "info"
        for path, risk in sensitive_paths.items():
            if path in url.lower():
                severity = risk
                break
        
        # 根据状态码调整风险
        if status_code == 403:
            severity = "medium" if severity == "info" else severity  # 禁止访问但仍暴露信息
        elif status_code == 401:
            severity = "medium"  # 需要认证
        
        finding = {
            "type": "exposed_directory",
            "name": f"暴露的目录/文件: {url.split('/')[-1] or '/'}",
            "description": f"在目标 {target} 上发现可访问的路径",
            "severity": severity,
            "cvss_score": self._get_cvss_score(severity),
            "evidence": f"URL: {url}, 状态码: {status_code}, 内容长度: {content_length}",
            "remediation": self._get_remediation(url, status_code),
            "details": {
                "target": target,
                "url": url,
                "status_code": status_code,
                "content_length": content_length,
                "headers": result.get("headers", {}),
                "redirect_location": result.get("redirect_location"),
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
    
    def _get_remediation(self, url: str, status_code: int) -> str:
        """获取修复建议"""
        if status_code == 403:
            return "访问已被禁止，但路径仍然暴露。建议在Web服务器配置中隐藏敏感路径。"
        elif status_code == 401:
            return "路径需要认证，但暴露了认证入口。确保使用强认证机制。"
        elif "admin" in url.lower() or "login" in url.lower():
            return "管理后台暴露。建议使用非常规路径或启用IP白名单。"
        elif ".git" in url or ".env" in url:
            return "敏感配置文件暴露。立即从生产环境移除这些文件。"
        elif "backup" in url.lower() or "bak" in url.lower():
            return "备份文件暴露。立即删除或移至非Web可访问目录。"
        else:
            return "评估此路径的必要性，如非必需则从Web服务器移除。"
    
    def scan_with_extensions(self, base_url: str, paths: List[str]) -> List[Dict[str, Any]]:
        """
        使用扩展名扫描
        
        Args:
            base_url: 基础URL
            paths: 路径列表
            
        Returns:
            List[Dict]: 扫描结果
        """
        extensions = self.web_config.get("extensions", [".php", ".html", ".txt", ".bak"])
        
        findings = []
        
        for path in paths:
            # 检查原始路径
            result = self._check_url(base_url, path)
            if result:
                finding = self._create_finding(base_url, result)
                findings.append(finding)
            
            # 检查带扩展名的路径
            for ext in extensions:
                path_with_ext = f"{path}{ext}" if not path.endswith(ext) else path
                result = self._check_url(base_url, path_with_ext)
                if result:
                    finding = self._create_finding(base_url, result)
                    findings.append(finding)
        
        return findings
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        执行目录爆破扫描
        
        Args:
            target: 目标URL（可以是域名或完整URL）
            
        Returns:
            List[Dict]: 扫描结果
        """
        self.logger.info(f"开始目录爆破扫描: {target}")
        
        # 确保URL格式正确
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        findings = []
        
        try:
            # 首先检查根目录是否可访问
            test_response = self.session.get(target, timeout=self.timeout)
            if test_response.status_code not in [200, 301, 302, 403, 401]:
                self.logger.warning(f"目标 {target} 不可访问，状态码: {test_response.status_code}")
                return findings
            
            self.logger.info(f"目标 {target} 可访问，开始爆破...")
            
            # 加载字典
            wordlist_path = self.web_config.get("directories_wordlist", "config/wordlists/directories.txt")
            words = self._load_wordlist(wordlist_path)
            
            # 设置并发数
            max_workers = self.scan_config.get("threads", 50)
            
            # 用于收集结果的列表
            results = []
            
            # 使用线程池并发扫描
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # 提交所有检查任务
                future_to_path = {
                    executor.submit(self._check_url, target, path): path 
                    for path in words
                }
                
                # 收集结果
                for future in concurrent.futures.as_completed(future_to_path):
                    path = future_to_path[future]
                    try:
                        result = future.result(timeout=self.timeout + 2)
                        if result:
                            results.append(result)
                            self.logger.debug(f"发现路径: {result['url']} [{result['status_code']}]")
                    except concurrent.futures.TimeoutError:
                        self.logger.debug(f"路径检查超时: {path}")
                    except Exception as e:
                        self.logger.debug(f"路径检查异常: {path}, 错误: {e}")
            
            # 转换为发现项
            for result in results:
                finding = self._create_finding(target, result)
                findings.append(finding)
            
            # 额外检查常见文件
            common_files = [
                "robots.txt", "sitemap.xml", "crossdomain.xml",
                "security.txt", "humans.txt", "ads.txt",
                ".well-known/security.txt", ".well-known/assetlinks.json"
            ]
            
            self.logger.info("检查常见文件...")
            for file in common_files:
                result = self._check_url(target, file)
                if result:
                    finding = self._create_finding(target, result)
                    findings.append(finding)
            
            # 检查HTTP方法
            self.logger.info("检查HTTP方法...")
            http_methods = self.web_config.get("http_methods", ["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            for method in http_methods:
                try:
                    response = self.session.request(method, target, timeout=self.timeout)
                    if method != "GET" and response.status_code not in [405, 501]:
                        finding = {
                            "type": "http_method",
                            "name": f"允许的HTTP方法: {method}",
                            "description": f"目标 {target} 允许 {method} 方法",
                            "severity": "low",
                            "cvss_score": 2.0,
                            "evidence": f"HTTP {method} 返回状态码: {response.status_code}",
                            "remediation": "限制不必要的HTTP方法，仅允许GET和POST",
                            "details": {
                                "target": target,
                                "method": method,
                                "status_code": response.status_code,
                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                            }
                        }
                        findings.append(finding)
                except:
                    pass
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"目录爆破扫描失败: {e}")
        except Exception as e:
            self.logger.error(f"扫描过程中发生错误: {e}")
        
        self.logger.info(f"目录爆破完成，发现 {len(findings)} 个暴露路径")
        return findings
    
    def scan_recursive(self, target: str, depth: int = 2) -> List[Dict[str, Any]]:
        """
        递归扫描目录
        
        Args:
            target: 目标URL
            depth: 递归深度
            
        Returns:
            List[Dict]: 扫描结果
        """
        if depth <= 0:
            return []
        
        self.logger.info(f"开始递归目录扫描，深度: {depth}")
        
        # 执行第一层扫描
        findings = self.scan(target)
        
        if depth > 1:
            # 从第一层结果中提取目录进行递归扫描
            directories = []
            for finding in findings[:10]:  # 限制递归数量
                url = finding["details"]["url"]
                status = finding["details"]["status_code"]
                
                # 只对目录类结果进行递归
                if status in [200, 301, 302] and not url.endswith(('.php', '.html', '.txt', '.xml', '.json')):
                    directories.append(url)
            
            # 递归扫描发现的目录
            for directory in directories:
                self.logger.info(f"递归扫描目录: {directory}")
                recursive_findings = self.scan_recursive(directory, depth - 1)
                findings.extend(recursive_findings)
        
        return findings


def main():
    """测试函数"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python directory_buster.py <目标URL>")
        print("示例: python directory_buster.py http://example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # 创建配置
    config = {
        "web": {
            "directories_wordlist": "config/wordlists/directories.txt",
            "extensions": [".php", ".html", ".txt", ".bak"]
        },
        "scanning": {
            "timeout": 10,
            "threads": 50,
            "user_agent": "DirectoryBuster/1.0"
        }
    }
    
    # 设置日志
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    scanner = DirectoryBuster(config)
    findings = scanner.scan(target)
    
    print(f"\n目录爆破结果 ({target}):")
    print("=" * 80)
    
    if findings:
        for finding in findings:
            print(f"路径: {finding['details']['url']}")
            print(f"状态码: {finding['details']['status_code']}")
            print(f"风险: {finding['severity']}")
            print(f"证据: {finding['evidence']}")
            print("-" * 80)
    else:
        print("未发现暴露的目录或文件")
    
    print(f"总计发现: {len(findings)} 个")


if __name__ == "__main__":
    main()