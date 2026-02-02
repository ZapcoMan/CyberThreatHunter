# CyberThreatHunter - 全面漏洞扫描工具
## Secondary development From DarkRevoltSociety 

一个全面的网络安全漏洞扫描工具，支持多种扫描功能，旨在帮助安全工程师和渗透测试人员发现网络和Web应用中的安全漏洞。

## 功能特性

### 🔍 网络扫描模块
- **端口扫描**：TCP/UDP端口扫描，服务识别
- **主机发现**：网络主机发现和存活检测
- **操作系统识别**：通过TCP/IP指纹识别操作系统

### 🌐 Web应用扫描模块
- **目录爆破**：常见Web目录和文件发现
- **子域名枚举**：DNS子域名发现
- **漏洞检测**：常见Web漏洞扫描（SQL注入、XSS、命令注入等）
- **SSL/TLS检查**：证书验证和配置检查

### 📊 报告模块
- **多种格式输出**：HTML、JSON、CSV、Excel报告
- **风险评级**：基于CVSS评分系统
- **详细证据**：包含PoC和复现步骤

## 项目结构

```
CyberThreatHunter/
├── main.py              # 主程序入口
├── requirements.txt     # Python依赖列表
├── config/
│   ├── config.yaml     # 配置文件
│   └── wordlists/      # 字典文件（目录/子域名）
├── modules/
│   ├── scanner.py      # 扫描器主类
│   ├── network/        # 网络扫描模块
│   ├── web/           # Web应用扫描模块
│   ├── dns/           # DNS扫描模块
│   └── utils/         # 工具函数
├── reports/            # 报告输出目录
└── tests/              # 测试文件
```

## 快速开始

### 1. 安装依赖
```bash
# 创建虚拟环境（推荐）
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 2. 基本使用
```bash
# 显示帮助信息
python main.py --help

# 扫描单个目标
python main.py --target example.com --scan web

# 扫描多个目标
python main.py --targets targets.txt --scan all

# 自定义端口扫描
python main.py --target 192.168.1.1 --ports 22,80,443,8080

# 输出报告
python main.py --target example.com --scan all --output report.html
```

### 3. 配置文件
编辑 `config/config.yaml` 自定义扫描参数：
```yaml
scanning:
  timeout: 10
  threads: 50
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    # 这里的 User-Agent 列表 不止这些 由于篇幅有限所以就只有这几个放在这里了 实际上 配置文件中有各种设备的User-Agent

web:
  directories_wordlist: "config/wordlists/directories.txt"
  extensions: [".php", ".html", ".txt", ".bak"]
```

## 模块说明

### 网络扫描 (`modules/network/`)
- `port_scanner.py`：TCP/UDP端口扫描
- `host_discovery.py`：网络主机发现
- `service_detector.py`：服务识别和版本检测

### Web扫描 (`modules/web/`)
- `directory_buster.py`：目录和文件爆破
- `vulnerability_scanner.py`：漏洞检测
- `ssl_checker.py`：SSL/TLS配置检查

### DNS扫描 (`modules/dns/`)
- `subdomain_enum.py`：子域名枚举
- `dns_records.py`：DNS记录查询

## 输出示例

```json
{
  "target": "example.com",
  "scan_time": "2024-01-15 10:30:00",
  "findings": [
    {
      "type": "web_vulnerability",
      "name": "SQL Injection",
      "severity": "High",
      "cvss_score": 8.5,
      "evidence": "/login.php?id=1'",
      "remediation": "使用参数化查询或ORM"
    }
  ]
}
```

## 注意事项

⚠️ **法律和道德使用**
- 仅扫描您拥有或已获得明确授权的目标
- 遵守当地法律法规
- 在生产环境扫描前获取书面授权

🔒 **安全建议**
- 在隔离的测试环境中使用
- 定期更新漏洞签名库
- 谨慎处理扫描结果，避免信息泄露

## 开发计划

- [ ] 集成漏洞数据库 (CVE/NVD)
- [ ] 添加WAF绕过技术
- [ ] 实现分布式扫描
- [ ] 添加API接口
- [ ] 开发Web管理界面

## 许可证

本项目仅供学习和授权测试使用。使用者需自行承担相关法律责任。

---
**作者**: Security Research Team  
**版本**: 1.0.0  
**最后更新**: 2024-01-15

## **在此致敬上游作者：[J09715/Vulnerability-Scanning-tool](https://github.com/J09715/Vulnerability-Scanning-tool) 本仓库做了更激进的修改，感谢原作者的开源精神**