#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CyberThreatHunter - 端口扫描模块
提供TCP/UDP端口扫描功能
"""

import socket
import threading
import concurrent.futures
import time
from typing import List, Dict, Any, Tuple
import ipaddress
import nmap
import logging


class PortScanner:
    """端口扫描器类"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化端口扫描器
        
        Args:
            config: 配置文件
        """
        self.config = config
        self.network_config = config.get("network", {})
        self.logger = logging.getLogger("VulnScanner.PortScanner")
        
        # 初始化nmap扫描器
        self.nm = nmap.PortScanner()
        
    def _parse_ports(self, ports_str: str) -> List[int]:
        """
        解析端口字符串
        
        Args:
            ports_str: 端口字符串，如 "80,443,8080" 或 "1-1000"
            
        Returns:
            List[int]: 端口列表
        """
        ports = []
        
        # 处理逗号分隔
        parts = ports_str.split(',')
        
        for part in parts:
            part = part.strip()
            
            # 处理范围
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    self.logger.warning(f"无效的端口范围: {part}")
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    self.logger.warning(f"无效的端口: {part}")
        
        return sorted(set(ports))  # 去重并排序
    
    def _check_port_tcp(self, target: str, port: int, timeout: float) -> Tuple[int, str, bool]:
        """
        检查TCP端口
        
        Returns:
            Tuple[端口, 服务名, 是否开放]
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # 尝试获取服务信息
                try:
                    sock.send(b'GET / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024)
                    service_info = self._guess_service(port, banner)
                except:
                    service_info = "unknown"
                
                sock.close()
                return port, service_info, True
            else:
                sock.close()
                return port, "", False
                
        except socket.timeout:
            return port, "", False
        except Exception as e:
            self.logger.debug(f"端口 {port} 检查失败: {e}")
            return port, "", False
    
    def _check_port_udp(self, target: str, port: int, timeout: float) -> Tuple[int, str, bool]:
        """
        检查UDP端口
        
        Returns:
            Tuple[端口, 服务名, 是否开放]
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # 发送空数据包
            sock.sendto(b'', (target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                if data:
                    service_info = self._guess_service(port, data)
                    return port, service_info, True
            except socket.timeout:
                # UDP端口开放但无响应是正常情况
                # 某些UDP服务只有在收到特定查询时才会响应
                return port, "udp_open", True
                
        except Exception as e:
            self.logger.debug(f"UDP端口 {port} 检查失败: {e}")
        
        return port, "", False
    
    def _guess_service(self, port: int, banner: bytes = None) -> str:
        """
        根据端口和横幅猜测服务
        
        Args:
            port: 端口号
            banner: 接收到的横幅数据
            
        Returns:
            str: 服务名称
        """
        # 常见端口映射
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1723: "pptp",
            3306: "mysql",
            3389: "ms-wbt-server",
            5900: "vnc",
            8080: "http-proxy",
            8443: "https-alt"
        }
        
        service = common_ports.get(port, "unknown")
        
        # 如果有横幅数据，尝试进一步识别
        if banner:
            banner_str = banner.decode('utf-8', errors='ignore').lower()
            
            if "apache" in banner_str:
                service = "apache"
            elif "nginx" in banner_str:
                service = "nginx"
            elif "iis" in banner_str:
                service = "iis"
            elif "ssh" in banner_str:
                service = "openssh"
            elif "mysql" in banner_str:
                service = "mysql"
            elif "postgresql" in banner_str:
                service = "postgresql"
            elif "redis" in banner_str:
                service = "redis"
        
        return service
    
    def _create_finding(self, target: str, port: int, service: str, protocol: str,
                       banner: str = "") -> Dict[str, Any]:
        """
        创建端口发现项
        
        Args:
            target: 目标地址
            port: 端口号
            service: 服务名称
            protocol: 协议 (tcp/udp)
            banner: 横幅信息
            
        Returns:
            Dict: 发现项
        """
        # 风险评估
        risk_ports = {
            21: "medium",  # FTP可能匿名访问
            22: "medium",  # SSH可能弱密码
            23: "high",    # Telnet明文传输
            25: "low",     # SMTP
            80: "low",     # HTTP
            443: "low",    # HTTPS
            445: "high",   # SMB可能漏洞
            3389: "high",  # RDP可能弱密码
            5900: "high",  # VNC可能无密码
        }
        
        severity = risk_ports.get(port, "info")
        
        finding = {
            "type": "open_port",
            "name": f"开放 {protocol.upper()} 端口: {port} ({service})",
            "description": f"在目标 {target} 上发现开放端口 {port}/{protocol}",
            "severity": severity,
            "cvss_score": self._get_cvss_score(severity),
            "evidence": f"端口 {port}/{protocol} 开放，服务: {service}",
            "remediation": self._get_remediation(port, protocol, service),
            "details": {
                "target": target,
                "port": port,
                "protocol": protocol,
                "service": service,
                "banner": banner[:200] if banner else "",  # 限制长度
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
    
    def _get_remediation(self, port: int, protocol: str, service: str) -> str:
        """获取修复建议"""
        remediation_map = {
            21: "禁用匿名FTP访问或使用SFTP/FTPS替代",
            22: "使用密钥认证，禁用密码登录，限制访问IP",
            23: "立即禁用Telnet，使用SSH替代",
            25: "配置SMTP身份验证，限制中继",
            445: "更新SMB服务，禁用SMBv1，限制网络访问",
            3389: "使用VPN访问，启用NLA，使用强密码策略",
            5900: "为VNC设置强密码，或使用SSH隧道",
        }
        
        default_remediation = f"评估端口 {port}/{protocol} ({service}) 的必要性，如非必需则关闭"
        
        return remediation_map.get(port, default_remediation)
    
    def scan_with_nmap(self, target: str, ports: str = None, 
                      scan_type: str = "tcp") -> List[Dict[str, Any]]:
        """
        使用nmap进行扫描
        
        Args:
            target: 扫描目标
            ports: 端口范围
            scan_type: 扫描类型 (tcp/udp)
            
        Returns:
            List[Dict]: 扫描结果
        """
        if ports is None:
            ports = self.network_config.get("default_ports", "1-1000")
        
        scan_args = f"-sS" if scan_type == "tcp" else f"-sU"
        
        try:
            self.logger.info(f"使用nmap扫描 {target}，端口: {ports}")
            
            self.nm.scan(targets=target, ports=ports, arguments=scan_args)
            
            findings = []
            
            if target in self.nm.all_hosts():
                host = self.nm[target]
                
                for proto in self.nm[target].all_protocols():
                    ports_info = host[proto]
                    
                    for port, info in ports_info.items():
                        service = info.get('name', 'unknown')
                        banner = info.get('product', '') + ' ' + info.get('version', '')
                        
                        finding = self._create_finding(
                            target=target,
                            port=port,
                            service=service,
                            protocol=proto,
                            banner=banner.strip()
                        )
                        
                        findings.append(finding)
            
            return findings
            
        except Exception as e:
            self.logger.error(f"nmap扫描失败: {e}")
            return []
    
    def scan_with_socket(self, target: str, ports: List[int] = None, 
                        protocol: str = "tcp") -> List[Dict[str, Any]]:
        """
        使用socket进行扫描（轻量级）
        
        Args:
            target: 扫描目标
            ports: 端口列表
            protocol: 协议 (tcp/udp)
            
        Returns:
            List[Dict]: 扫描结果
        """
        if ports is None:
            ports_str = self.network_config.get("default_ports", "21,22,23,25,53,80,110,443,445,3389")
            ports = self._parse_ports(ports_str)
        
        timeout = self.network_config.get("tcp_scan_timeout", 2.0)
        if protocol == "udp":
            timeout = self.network_config.get("udp_scan_timeout", 5.0)
        
        max_workers = self.network_config.get("tcp_scan_threads", 100)
        
        findings = []
        open_ports = []
        
        self.logger.info(f"使用socket扫描 {target}，端口数: {len(ports)}，协议: {protocol}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有端口检查任务
            if protocol == "tcp":
                futures = [
                    executor.submit(self._check_port_tcp, target, port, timeout) 
                    for port in ports
                ]
            else:
                futures = [
                    executor.submit(self._check_port_udp, target, port, timeout) 
                    for port in ports
                ]
            
            # 收集结果
            for future in concurrent.futures.as_completed(futures):
                try:
                    port, service, is_open = future.result(timeout=timeout + 1)
                    
                    if is_open:
                        open_ports.append((port, service))
                        
                        finding = self._create_finding(
                            target=target,
                            port=port,
                            service=service,
                            protocol=protocol
                        )
                        
                        findings.append(finding)
                        
                except concurrent.futures.TimeoutError:
                    self.logger.warning("端口检查超时")
                except Exception as e:
                    self.logger.debug(f"端口检查异常: {e}")
        
        self.logger.info(f"发现 {len(open_ports)} 个开放端口")
        return findings
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        执行端口扫描
        
        Args:
            target: 扫描目标
            
        Returns:
            List[Dict]: 扫描结果
        """
        self.logger.info(f"开始端口扫描: {target}")
        
        findings = []
        
        try:
            # 首先尝试使用nmap（如果可用）
            try:
                nmap_findings = self.scan_with_nmap(target)
                findings.extend(nmap_findings)
                
                if nmap_findings:
                    self.logger.info(f"nmap扫描完成，发现 {len(nmap_findings)} 个开放端口")
                    return findings
                    
            except Exception as e:
                self.logger.warning(f"nmap不可用，回退到socket扫描: {e}")
            
            # 使用socket扫描作为备选
            socket_findings = self.scan_with_socket(target)
            findings.extend(socket_findings)
            
            # UDP扫描（可选）
            udp_scan_enabled = self.network_config.get("udp_scan_enabled", False)
            if udp_scan_enabled:
                common_udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520]
                udp_findings = self.scan_with_socket(target, common_udp_ports, "udp")
                findings.extend(udp_findings)
            
        except Exception as e:
            self.logger.error(f"端口扫描失败: {e}")
        
        self.logger.info(f"端口扫描完成，总计发现 {len(findings)} 个开放端口")
        return findings
    
    def scan_network_range(self, network_range: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        扫描整个网络范围
        
        Args:
            network_range: 网络范围，如 "192.168.1.0/24"
            
        Returns:
            Dict: 各主机的扫描结果
        """
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            results = {}
            
            self.logger.info(f"开始扫描网络范围: {network_range}，主机数: {network.num_addresses - 2}")
            
            # 限制扫描的主机数量
            max_hosts = self.network_config.get("max_network_hosts", 254)
            hosts_scanned = 0
            
            for ip in network.hosts():
                if hosts_scanned >= max_hosts:
                    self.logger.warning(f"达到最大主机扫描限制: {max_hosts}")
                    break
                
                target = str(ip)
                self.logger.info(f"扫描主机: {target}")
                
                findings = self.scan(target)
                
                if findings:
                    results[target] = findings
                
                hosts_scanned += 1
                
                # 延迟以避免触发防火墙
                time.sleep(0.1)
            
            self.logger.info(f"网络扫描完成，扫描 {hosts_scanned} 台主机，发现 {len(results)} 台有开放端口")
            
            return results
            
        except ValueError as e:
            self.logger.error(f"无效的网络范围: {e}")
            return {}


def main():
    """测试函数"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python port_scanner.py <目标> [端口范围]")
        print("示例: python port_scanner.py 127.0.0.1 1-1000")
        sys.exit(1)
    
    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else "1-1000"
    
    # 创建配置
    config = {
        "network": {
            "default_ports": "1-1000",
            "tcp_scan_timeout": 2.0,
            "tcp_scan_threads": 100,
            "udp_scan_timeout": 5.0
        }
    }
    
    scanner = PortScanner(config)
    findings = scanner.scan_with_socket(target, scanner._parse_ports(ports))
    
    print(f"\n扫描结果 ({target}):")
    print("-" * 60)
    
    for finding in findings:
        print(f"端口: {finding['details']['port']}/{finding['details']['protocol']}")
        print(f"服务: {finding['details']['service']}")
        print(f"风险: {finding['severity']}")
        print(f"证据: {finding['evidence']}")
        print("-" * 60)


if __name__ == "__main__":
    main()