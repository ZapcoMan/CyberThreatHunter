#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CyberThreatHunter - 漏洞扫描器主模块
提供统一的扫描接口和结果管理
"""

import yaml
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict
import concurrent.futures
from pathlib import Path

# 导入子模块
from modules.network.port_scanner import PortScanner
from modules.web.directory_buster import DirectoryBuster
from modules.web.vulnerability_scanner import VulnerabilityScanner
from modules.dns.subdomain_enum import SubdomainEnumerator
from modules.utils.output_reporter import OutputReporter


@dataclass
class ScanResult:
    """扫描结果数据类"""
    target: str
    scan_type: str
    start_time: str
    end_time: str = field(default_factory=lambda: datetime.now().isoformat())
    findings: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "pending"  # pending, running, completed, failed
    errors: List[str] = field(default_factory=list)
    scan_config: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)
    
    def add_finding(self, finding: Dict[str, Any]) -> None:
        """添加发现项"""
        self.findings.append(finding)
    
    def add_error(self, error: str) -> None:
        """添加错误信息"""
        self.errors.append(error)
    
    def calculate_stats(self) -> Dict[str, Any]:
        """计算统计信息"""
        stats = {
            "total_findings": len(self.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in self.findings:
            severity = finding.get("severity", "info").lower()
            if severity in stats:
                stats[severity] += 1
        
        return stats


class VulnerabilityScannerMain:
    """主扫描器类"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        初始化扫描器
        
        Args:
            config_path: 配置文件路径
        """
        self.config = self._load_config(config_path)
        self.results: List[ScanResult] = []
        self.scanners = {}
        self.logger = self._setup_logging()
        
        # 初始化子扫描器
        self._init_scanners()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.warning(f"配置文件 {config_path} 未找到，使用默认配置")
            return self._get_default_config()
        except yaml.YAMLError as e:
            raise ValueError(f"配置文件解析错误: {e}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            "scanning": {
                "timeout": 10,
                "threads": 50,
                "retries": 2,
                "delay": 0.1,
                "user_agent": "VulnerabilityScanner/1.0"
            },
            "output": {
                "report_dir": "reports",
                "default_format": "html"
            }
        }
    
    def _setup_logging(self) -> logging.Logger:
        """设置日志"""
        logger = logging.getLogger("VulnScanner")
        logger.setLevel(logging.INFO)
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # 文件处理器
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(
            log_dir / f"scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _init_scanners(self) -> None:
        """初始化子扫描器"""
        try:
            # 端口扫描器
            self.scanners['port'] = PortScanner(self.config)
            
            # 目录爆破扫描器
            self.scanners['directory'] = DirectoryBuster(self.config)
            
            # 漏洞扫描器
            self.scanners['vulnerability'] = VulnerabilityScanner(self.config)
            
            # 子域名枚举器
            self.scanners['subdomain'] = SubdomainEnumerator(self.config)
            
            self.logger.info("所有扫描器初始化完成")
            
        except Exception as e:
            self.logger.error(f"扫描器初始化失败: {e}")
            raise
    
    def scan(self, target: str, scan_types: List[str] = None) -> ScanResult:
        """
        执行扫描
        
        Args:
            target: 扫描目标（IP或域名）
            scan_types: 扫描类型列表，可选值：port, directory, vulnerability, subdomain
            
        Returns:
            ScanResult: 扫描结果
        """
        if scan_types is None:
            scan_types = ["port", "directory", "vulnerability", "subdomain"]
        
        scan_result = ScanResult(
            target=target,
            scan_type=",".join(scan_types),
            start_time=datetime.now().isoformat(),
            status="running"
        )
        
        self.logger.info(f"开始扫描目标: {target}")
        self.logger.info(f"扫描类型: {scan_types}")
        
        try:
            for scan_type in scan_types:
                if scan_type in self.scanners:
                    self.logger.info(f"执行 {scan_type} 扫描...")
                    
                    scanner = self.scanners[scan_type]
                    findings = scanner.scan(target)
                    
                    for finding in findings:
                        scan_result.add_finding(finding)
                    
                    self.logger.info(f"{scan_type} 扫描完成，发现 {len(findings)} 个问题")
                else:
                    error_msg = f"未知的扫描类型: {scan_type}"
                    self.logger.warning(error_msg)
                    scan_result.add_error(error_msg)
            
            scan_result.status = "completed"
            scan_result.end_time = datetime.now().isoformat()
            
            stats = scan_result.calculate_stats()
            self.logger.info(f"扫描完成，总计发现 {stats['total_findings']} 个问题")
            self.logger.info(f"风险分布: 严重={stats['critical']}, 高危={stats['high']}, "
                           f"中危={stats['medium']}, 低危={stats['low']}, 信息={stats['info']}")
            
        except Exception as e:
            self.logger.error(f"扫描过程中发生错误: {e}")
            scan_result.status = "failed"
            scan_result.add_error(str(e))
            scan_result.end_time = datetime.now().isoformat()
        
        self.results.append(scan_result)
        return scan_result
    
    def scan_multiple(self, targets: List[str], scan_types: List[str] = None,
                      max_workers: int = None) -> List[ScanResult]:
        """
        并发扫描多个目标
        
        Args:
            targets: 目标列表
            scan_types: 扫描类型列表
            max_workers: 最大并发数
            
        Returns:
            List[ScanResult]: 扫描结果列表
        """
        if max_workers is None:
            max_workers = self.config.get("scanning", {}).get("threads", 10)
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有扫描任务
            future_to_target = {
                executor.submit(self.scan, target, scan_types): target 
                for target in targets
            }
            
            # 收集结果
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result(timeout=300)  # 5分钟超时
                    results.append(result)
                    self.logger.info(f"目标 {target} 扫描完成")
                except concurrent.futures.TimeoutError:
                    self.logger.error(f"目标 {target} 扫描超时")
                except Exception as e:
                    self.logger.error(f"目标 {target} 扫描失败: {e}")
        
        return results
    
    def generate_report(self, result: ScanResult, format: str = None,
                       output_path: str = None) -> str:
        """
        生成报告
        
        Args:
            result: 扫描结果
            format: 报告格式（html, json, csv, excel）
            output_path: 输出路径
            
        Returns:
            str: 报告文件路径
        """
        if format is None:
            format = self.config.get("output", {}).get("default_format", "html")
        
        if output_path is None:
            report_dir = Path(self.config.get("output", {}).get("report_dir", "reports"))
            report_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{result.target}_{timestamp}.{format}"
            output_path = str(report_dir / filename)
        
        reporter = OutputReporter(self.config)
        report_path = reporter.generate_report(result.to_dict(), format, output_path)
        
        self.logger.info(f"报告已生成: {report_path}")
        return report_path
    
    def export_results(self, format: str = "json", output_dir: str = "reports") -> List[str]:
        """
        导出所有扫描结果
        
        Args:
            format: 导出格式
            output_dir: 输出目录
            
        Returns:
            List[str]: 导出文件路径列表
        """
        export_paths = []
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        for result in self.results:
            if result.status == "completed":
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"result_{result.target}_{timestamp}.{format}"
                output_path = str(output_dir / filename)
                
                reporter = OutputReporter(self.config)
                report_path = reporter.generate_report(result.to_dict(), format, output_path)
                export_paths.append(report_path)
        
        return export_paths
    
    def get_summary(self) -> Dict[str, Any]:
        """获取扫描摘要"""
        summary = {
            "total_scans": len(self.results),
            "completed": 0,
            "failed": 0,
            "total_findings": 0,
            "findings_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "targets": []
        }
        
        for result in self.results:
            if result.status == "completed":
                summary["completed"] += 1
                stats = result.calculate_stats()
                summary["total_findings"] += stats["total_findings"]
                
                for severity in summary["findings_by_severity"]:
                    summary["findings_by_severity"][severity] += stats.get(severity, 0)
            elif result.status == "failed":
                summary["failed"] += 1
            
            summary["targets"].append({
                "target": result.target,
                "status": result.status,
                "findings_count": len(result.findings)
            })
        
        return summary
    
    def clear_results(self) -> None:
        """清除所有扫描结果"""
        self.results.clear()
        self.logger.info("所有扫描结果已清除")


def main():
    """命令行入口点"""
    import argparse
    
    parser = argparse.ArgumentParser(description="全面漏洞扫描工具")
    parser.add_argument("--target", type=str, help="单个扫描目标")
    parser.add_argument("--targets", type=str, help="包含多个目标的文件路径")
    parser.add_argument("--scan", type=str, default="all",
                       choices=["all", "port", "directory", "vulnerability", "subdomain"],
                       help="扫描类型")
    parser.add_argument("--output", type=str, help="报告输出路径")
    parser.add_argument("--format", type=str, default="html",
                       choices=["html", "json", "csv", "excel"],
                       help="报告格式")
    parser.add_argument("--config", type=str, default="config/config.yaml",
                       help="配置文件路径")
    parser.add_argument("--threads", type=int, help="并发线程数")
    
    args = parser.parse_args()
    
    # 创建扫描器
    scanner = VulnerabilityScannerMain(args.config)
    
    # 解析扫描类型
    if args.scan == "all":
        scan_types = ["port", "directory", "vulnerability", "subdomain"]
    else:
        scan_types = [args.scan]
    
    # 执行扫描
    if args.target:
        results = [scanner.scan(args.target, scan_types)]
    elif args.targets:
        with open(args.targets, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        results = scanner.scan_multiple(targets, scan_types)
    else:
        print("错误: 必须指定 --target 或 --targets 参数")
        return
    
    # 生成报告
    for result in results:
        if result.status == "completed":
            scanner.generate_report(result, args.format, args.output)
    
    # 显示摘要
    summary = scanner.get_summary()
    print("\n" + "="*60)
    print("扫描摘要:")
    print(f"总扫描数: {summary['total_scans']}")
    print(f"成功: {summary['completed']}")
    print(f"失败: {summary['failed']}")
    print(f"总发现数: {summary['total_findings']}")
    print("风险分布:")
    for severity, count in summary['findings_by_severity'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    print("="*60)


if __name__ == "__main__":
    main()