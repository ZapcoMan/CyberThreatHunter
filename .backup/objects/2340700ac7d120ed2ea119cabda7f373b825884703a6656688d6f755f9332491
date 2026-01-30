#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
输出报告模块
生成各种格式的扫描报告（HTML、JSON、CSV、Excel）
"""

import json
import csv
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import pandas as pd


class OutputReporter:
    """报告生成器"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化报告生成器
        
        Args:
            config: 配置文件
        """
        self.config = config
        self.output_config = config.get("output", {})
        self.logger = logging.getLogger("VulnScanner.OutputReporter")
        
    def generate_report(self, result: Dict[str, Any], format: str = "html",
                       output_path: Optional[str] = None) -> str:
        """
        生成报告
        
        Args:
            result: 扫描结果
            format: 报告格式
            output_path: 输出路径
            
        Returns:
            str: 报告文件路径
        """
        if format.lower() == "html":
            return self._generate_html_report(result, output_path)
        elif format.lower() == "json":
            return self._generate_json_report(result, output_path)
        elif format.lower() == "csv":
            return self._generate_csv_report(result, output_path)
        elif format.lower() == "excel":
            return self._generate_excel_report(result, output_path)
        else:
            raise ValueError(f"不支持的报告格式: {format}")
    
    def _generate_html_report(self, result: Dict[str, Any], 
                             output_path: Optional[str] = None) -> str:
        """
        生成HTML报告
        
        Args:
            result: 扫描结果
            output_path: 输出路径
            
        Returns:
            str: HTML文件路径
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = result.get("target", "unknown").replace(".", "_").replace("/", "_")
            output_path = f"reports/report_{target}_{timestamp}.html"
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 统计数据
        stats = self._calculate_stats(result.get("findings", []))
        
        # 生成HTML内容
        html_content = self._create_html_content(result, stats)
        
        # 写入文件
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML报告已生成: {output_path}")
        return str(output_path)
    
    def _create_html_content(self, result: Dict[str, Any], stats: Dict[str, Any]) -> str:
        """创建HTML内容"""
        target = result.get("target", "Unknown")
        start_time = result.get("start_time", "")
        end_time = result.get("end_time", "")
        findings = result.get("findings", [])
        
        # 风险等级颜色映射
        severity_colors = {
            "critical": "#dc3545",  # 红色
            "high": "#fd7e14",      # 橙色
            "medium": "#ffc107",    # 黄色
            "low": "#28a745",       # 绿色
            "info": "#17a2b8"       # 蓝色
        }
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>漏洞扫描报告 - {target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
            margin-top: 10px;
        }}
        
        .summary {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .stat-label {{
            font-size: 0.9em;
            color: #6c757d;
            margin-top: 5px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
            margin-right: 5px;
        }}
        
        .findings-table {{
            width: 100%;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            margin-bottom: 30px;
        }}
        
        .findings-table th {{
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }}
        
        .findings-table td {{
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
            vertical-align: top;
        }}
        
        .findings-table tr:hover {{
            background: #f8f9fa;
        }}
        
        .details-panel {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-top: 10px;
            display: none;
        }}
        
        .details-panel pre {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            overflow: auto;
            font-size: 0.9em;
        }}
        
        .toggle-details {{
            background: none;
            border: none;
            color: #667eea;
            cursor: pointer;
            font-size: 0.9em;
            padding: 5px 10px;
            border-radius: 4px;
        }}
        
        .toggle-details:hover {{
            background: #e9ecef;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #dee2e6;
        }}
        
        .risk-chart {{
            height: 200px;
            background: linear-gradient(90deg, 
                #dc3545 {stats.get('critical_percent', 0)}%, 
                #fd7e14 {stats.get('high_percent', 0)}%, 
                #ffc107 {stats.get('medium_percent', 0)}%, 
                #28a745 {stats.get('low_percent', 0)}%, 
                #17a2b8 {stats.get('info_percent', 0)}%);
            border-radius: 8px;
            margin: 20px 0;
        }}
        
        .legend {{
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 20px;
            flex-wrap: wrap;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 4px;
        }}
    </style>
    <script>
        function toggleDetails(id) {{
            var panel = document.getElementById('details-' + id);
            if (panel.style.display === 'none' || panel.style.display === '') {{
                panel.style.display = 'block';
            }} else {{
                panel.style.display = 'none';
            }}
        }}
        
        function expandAll() {{
            var panels = document.querySelectorAll('.details-panel');
            panels.forEach(function(panel) {{
                panel.style.display = 'block';
            }});
        }}
        
        function collapseAll() {{
            var panels = document.querySelectorAll('.details-panel');
            panels.forEach(function(panel) {{
                panel.style.display = 'none';
            }});
        }}
    </script>
</head>
<body>
    <div class="header">
        <h1>🔍 漏洞扫描报告</h1>
        <div class="subtitle">
            目标: <strong>{target}</strong> | 
            扫描时间: {start_time} - {end_time} | 
            扫描状态: {result.get('status', 'unknown')}
        </div>
    </div>
    
    <div class="summary">
        <h2>📊 扫描摘要</h2>
        <div class="risk-chart"></div>
        
        <div class="legend">
            <div class="legend-item">
                <div class="legend-color" style="background-color: #dc3545;"></div>
                <span>严重 ({stats.get('critical', 0)})</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #fd7e14;"></div>
                <span>高危 ({stats.get('high', 0)})</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #ffc107;"></div>
                <span>中危 ({stats.get('medium', 0)})</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #28a745;"></div>
                <span>低危 ({stats.get('low', 0)})</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #17a2b8;"></div>
                <span>信息 ({stats.get('info', 0)})</span>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{stats.get('total_findings', 0)}</div>
                <div class="stat-label">总发现数</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats.get('critical', 0)}</div>
                <div class="stat-label">严重漏洞</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats.get('high', 0)}</div>
                <div class="stat-label">高危漏洞</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats.get('medium', 0)}</div>
                <div class="stat-label">中危漏洞</div>
            </div>
        </div>
        
        <div style="margin-top: 20px; text-align: center;">
            <button onclick="expandAll()" style="margin-right: 10px; padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer;">
                展开所有详情
            </button>
            <button onclick="collapseAll()" style="padding: 8px 16px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer;">
                收起所有详情
            </button>
        </div>
    </div>
    
    <h2>📋 漏洞详情</h2>
    <table class="findings-table">
        <thead>
            <tr>
                <th width="5%">ID</th>
                <th width="20%">漏洞类型</th>
                <th width="15%">风险等级</th>
                <th width="40%">描述</th>
                <th width="20%">操作</th>
            </tr>
        </thead>
        <tbody>
"""
        
        # 添加漏洞行
        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "info").lower()
            color = severity_colors.get(severity, "#6c757d")
            
            html += f"""
            <tr>
                <td>{i}</td>
                <td><strong>{finding.get('type', 'Unknown')}</strong></td>
                <td><span class="severity-badge" style="background-color: {color};">{severity.upper()}</span></td>
                <td>{finding.get('description', 'No description')}</td>
                <td>
                    <button class="toggle-details" onclick="toggleDetails({i})">查看详情</button>
                </td>
            </tr>
            <tr>
                <td colspan="5">
                    <div class="details-panel" id="details-{i}">
                        <h4>详细信息</h4>
                        <p><strong>名称:</strong> {finding.get('name', 'N/A')}</p>
                        <p><strong>CVSS评分:</strong> {finding.get('cvss_score', 'N/A')}</p>
                        <p><strong>证据:</strong> {finding.get('evidence', 'N/A')}</p>
                        <p><strong>修复建议:</strong> {finding.get('remediation', 'N/A')}</p>
                        
                        <h4>原始数据</h4>
                        <pre>{json.dumps(finding.get('details', {}), indent=2, ensure_ascii=False)}</pre>
                    </div>
                </td>
            </tr>
"""
        
        html += """
        </tbody>
    </table>
    
    <div class="footer">
        <p>📅 报告生成时间: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        <p>🔒 本报告仅供授权测试使用，请妥善保管</p>
        <p>⚠️ 所有发现均需在获得授权的前提下进行验证和修复</p>
    </div>
</body>
</html>"""
        
        return html
    
    def _calculate_stats(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """计算统计数据"""
        stats = {
            "total_findings": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in stats:
                stats[severity] += 1
        
        # 计算百分比
        total = stats["total_findings"]
        if total > 0:
            for severity in ["critical", "high", "medium", "low", "info"]:
                stats[f"{severity}_percent"] = (stats[severity] / total) * 100
        else:
            for severity in ["critical", "high", "medium", "low", "info"]:
                stats[f"{severity}_percent"] = 0
        
        return stats
    
    def _generate_json_report(self, result: Dict[str, Any], 
                            output_path: Optional[str] = None) -> str:
        """
        生成JSON报告
        
        Args:
            result: 扫描结果
            output_path: 输出路径
            
        Returns:
            str: JSON文件路径
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = result.get("target", "unknown").replace(".", "_").replace("/", "_")
            output_path = f"reports/report_{target}_{timestamp}.json"
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 添加统计信息
        stats = self._calculate_stats(result.get("findings", []))
        result["statistics"] = stats
        result["report_generated"] = datetime.now().isoformat()
        
        # 写入JSON文件
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"JSON报告已生成: {output_path}")
        return str(output_path)
    
    def _generate_csv_report(self, result: Dict[str, Any], 
                            output_path: Optional[str] = None) -> str:
        """
        生成CSV报告
        
        Args:
            result: 扫描结果
            output_path: 输出路径
            
        Returns:
            str: CSV文件路径
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = result.get("target", "unknown").replace(".", "_").replace("/", "_")
            output_path = f"reports/report_{target}_{timestamp}.csv"
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        findings = result.get("findings", [])
        
        if findings:
            # 提取CSV字段
            fieldnames = ["id", "type", "name", "severity", "cvss_score", 
                         "description", "evidence", "remediation", "timestamp"]
            
            with open(output_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for i, finding in enumerate(findings, 1):
                    row = {
                        "id": i,
                        "type": finding.get("type", ""),
                        "name": finding.get("name", ""),
                        "severity": finding.get("severity", ""),
                        "cvss_score": finding.get("cvss_score", ""),
                        "description": finding.get("description", ""),
                        "evidence": finding.get("evidence", "")[:500],  # 限制长度
                        "remediation": finding.get("remediation", ""),
                        "timestamp": finding.get("details", {}).get("timestamp", "")
                    }
                    writer.writerow(row)
        
        self.logger.info(f"CSV报告已生成: {output_path}")
        return str(output_path)
    
    def _generate_excel_report(self, result: Dict[str, Any], 
                              output_path: Optional[str] = None) -> str:
        """
        生成Excel报告
        
        Args:
            result: 扫描结果
            output_path: 输出路径
            
        Returns:
            str: Excel文件路径
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = result.get("target", "unknown").replace(".", "_").replace("/", "_")
            output_path = f"reports/report_{target}_{timestamp}.xlsx"
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        findings = result.get("findings", [])
        
        if findings:
            # 准备数据
            data = []
            for i, finding in enumerate(findings, 1):
                data.append({
                    "ID": i,
                    "漏洞类型": finding.get("type", ""),
                    "漏洞名称": finding.get("name", ""),
                    "风险等级": finding.get("severity", ""),
                    "CVSS评分": finding.get("cvss_score", ""),
                    "描述": finding.get("description", ""),
                    "证据": finding.get("evidence", "")[:500],
                    "修复建议": finding.get("remediation", ""),
                    "发现时间": finding.get("details", {}).get("timestamp", ""),
                    "目标": finding.get("details", {}).get("target", "")
                })
            
            # 创建DataFrame
            df = pd.DataFrame(data)
            
            # 写入Excel
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='漏洞详情', index=False)
                
                # 添加摘要工作表
                stats = self._calculate_stats(findings)
                summary_data = {
                    "统计项": ["总发现数", "严重漏洞", "高危漏洞", "中危漏洞", "低危漏洞", "信息"],
                    "数量": [
                        stats["total_findings"],
                        stats["critical"],
                        stats["high"],
                        stats["medium"],
                        stats["low"],
                        stats["info"]
                    ]
                }
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='扫描摘要', index=False)
        
        self.logger.info(f"Excel报告已生成: {output_path}")
        return str(output_path)
    
    def generate_summary_report(self, results: List[Dict[str, Any]], 
                               format: str = "html") -> str:
        """
        生成多个结果的汇总报告
        
        Args:
            results: 多个扫描结果
            format: 报告格式
            
        Returns:
            str: 报告文件路径
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"reports/summary_report_{timestamp}.{format}"
        
        if format.lower() == "html":
            return self._generate_summary_html(results, output_path)
        elif format.lower() == "json":
            return self._generate_summary_json(results, output_path)
        else:
            raise ValueError(f"汇总报告不支持格式: {format}")
    
    def _generate_summary_html(self, results: List[Dict[str, Any]], 
                              output_path: str) -> str:
        """生成汇总HTML报告"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 计算总体统计
        total_stats = {
            "total_targets": len(results),
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        target_stats = []
        
        for result in results:
            stats = self._calculate_stats(result.get("findings", []))
            target_stats.append({
                "target": result.get("target", "Unknown"),
                "status": result.get("status", "unknown"),
                "findings": stats["total_findings"],
                "critical": stats["critical"],
                "high": stats["high"],
                "medium": stats["medium"]
            })
            
            total_stats["total_findings"] += stats["total_findings"]
            total_stats["critical"] += stats["critical"]
            total_stats["high"] += stats["high"]
            total_stats["medium"] += stats["medium"]
            total_stats["low"] += stats["low"]
            total_stats["info"] += stats["info"]
        
        # 生成HTML
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>漏洞扫描汇总报告</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        
        .summary {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .stat-label {{
            font-size: 0.9em;
            color: #6c757d;
            margin-top: 5px;
        }}
        
        table {{
            width: 100%;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            margin-bottom: 30px;
        }}
        
        th {{
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }}
        
        td {{
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #dee2e6;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 漏洞扫描汇总报告</h1>
        <div class="subtitle">
            扫描目标数: {total_stats['total_targets']} | 
            总发现数: {total_stats['total_findings']} | 
            报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
    
    <div class="summary">
        <h2>总体统计</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{total_stats['total_targets']}</div>
                <div class="stat-label">扫描目标</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_stats['total_findings']}</div>
                <div class="stat-label">总漏洞数</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_stats['critical']}</div>
                <div class="stat-label">严重漏洞</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_stats['high']}</div>
                <div class="stat-label">高危漏洞</div>
            </div>
        </div>
    </div>
    
    <h2>各目标扫描结果</h2>
    <table>
        <thead>
            <tr>
                <th>目标</th>
                <th>扫描状态</th>
                <th>总发现数</th>
                <th>严重</th>
                <th>高危</th>
                <th>中危</th>
            </tr>
        </thead>
        <tbody>
"""
        
        for stat in target_stats:
            html += f"""
            <tr>
                <td>{stat['target']}</td>
                <td>{stat['status']}</td>
                <td>{stat['findings']}</td>
                <td>{stat['critical']}</td>
                <td>{stat['high']}</td>
                <td>{stat['medium']}</td>
            </tr>
"""
        
        html += """
        </tbody>
    </table>
    
    <div class="footer">
        <p>🔒 本报告仅供授权测试使用，请妥善保管</p>
        <p>⚠️ 所有发现均需在获得授权的前提下进行验证和修复</p>
    </div>
</body>
</html>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        self.logger.info(f"汇总HTML报告已生成: {output_path}")
        return str(output_path)
    
    def _generate_summary_json(self, results: List[Dict[str, Any]], 
                              output_path: str) -> str:
        """生成汇总JSON报告"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        summary = {
            "report_type": "summary",
            "generated": datetime.now().isoformat(),
            "total_targets": len(results),
            "targets": []
        }
        
        for result in results:
            stats = self._calculate_stats(result.get("findings", []))
            target_info = {
                "target": result.get("target"),
                "status": result.get("status"),
                "start_time": result.get("start_time"),
                "end_time": result.get("end_time"),
                "statistics": stats
            }
            summary["targets"].append(target_info)
        
        # 写入文件
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"汇总JSON报告已生成: {output_path}")
        return str(output_path)


def main():
    """测试函数"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python output_reporter.py <测试数据文件>")
        print("示例: python output_reporter.py test_data.json")
        sys.exit(1)
    
    test_file = sys.argv[1]
    
    # 加载测试数据
    try:
        with open(test_file, 'r') as f:
            test_data = json.load(f)
    except FileNotFoundError:
        # 创建示例测试数据
        test_data = {
            "target": "example.com",
            "start_time": "2024-01-15T10:30:00",
            "end_time": "2024-01-15T10:35:00",
            "status": "completed",
            "findings": [
                {
                    "type": "sql_injection",
                    "name": "SQL注入漏洞",
                    "description": "在登录页面发现SQL注入漏洞",
                    "severity": "critical",
                    "cvss_score": 9.0,
                    "evidence": "参数: username, 载荷: ' OR '1'='1",
                    "remediation": "使用参数化查询",
                    "details": {
                        "target": "example.com",
                        "parameter": "username",
                        "payload": "' OR '1'='1",
                        "timestamp": "2024-01-15 10:31:00"
                    }
                },
                {
                    "type": "xss",
                    "name": "跨站脚本漏洞",
                    "description": "在搜索框发现反射型XSS",
                    "severity": "high",
                    "cvss_score": 7.0,
                    "evidence": "参数: search, 载荷: <script>alert(1)</script>",
                    "remediation": "对用户输入进行HTML编码",
                    "details": {
                        "target": "example.com",
                        "parameter": "search",
                        "payload": "<script>alert(1)</script>",
                        "timestamp": "2024-01-15 10:32:00"
                    }
                }
            ]
        }
    
    # 创建配置
    config = {
        "output": {
            "report_dir": "reports",
            "default_format": "html"
        }
    }
    
    # 设置日志
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    reporter = OutputReporter(config)
    
    # 生成各种格式的报告
    print("生成测试报告...")
    html_path = reporter.generate_report(test_data, "html")
    json_path = reporter.generate_report(test_data, "json")
    csv_path = reporter.generate_report(test_data, "csv")
    excel_path = reporter.generate_report(test_data, "excel")
    
    print(f"HTML报告: {html_path}")
    print(f"JSON报告: {json_path}")
    print(f"CSV报告: {csv_path}")
    print(f"Excel报告: {excel_path}")


if __name__ == "__main__":
    main()