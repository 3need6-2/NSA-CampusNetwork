# 校园网态势感知系统 - 流量分析画像与安全可视化模块

![CI](https://github.com/Arbeiter-bit/NSA-CampusNetwork/workflows/CI/badge.svg)
![Lint](https://github.com/Arbeiter-bit/NSA-CampusNetwork/workflows/Lint/badge.svg)
![Docker Build](https://github.com/Arbeiter-bit/NSA-CampusNetwork/workflows/Docker%20Build/badge.svg)

校园网态势感知系统是一款专注于校园网络流量分析、用户行为画像和安全可视化的综合平台。系统通过上传 CSV 格式的流量样本，利用规则引擎、机器学习（IsolationForest）和可选 AI 复核（DeepSeek）等多层分析机制，帮助网络管理员快速识别异常行为和潜在安全威胁。

## 核心功能

- **流量统计与排行**：总流量、包数量、用户数、IP 数、用户流量排名、应用类别分布
- **流量趋势分析**：按小时汇总流量，生成趋势图和活跃时段统计
- **用户应用分析**：每个用户的应用占比、协议占比、端口访问和 DNS 行为
- **用户画像**：自动生成用户标签（应用、时段、安全），输出 JSON 数据
- **AI 安全审查**：本地规则引擎检测端口扫描、敏感服务、异常流量等
- **DeepSeek 复核**：可选远程 AI 防守复核，仅发送汇总风险
- **ML 异常检测**：IsolationForest 无监督异常评分
- **实时态势大屏**：SSE 驱动的实时流量回放、告警和曲线
- **智能拦截建议**：限速、二次认证、隔离策略
- **可视化图表**：Chart.js 深色态势感知界面

## 快速开始

```bash
# 克隆仓库
git clone https://github.com/Arbeiter-bit/NSA-CampusNetwork.git
cd NSA-CampusNetwork

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 启动应用
python app.py

# 浏览器访问
# http://localhost:5001
```

或使用 Docker：

```bash
docker-compose up --build
```

## 技术栈

| 分类 | 技术 |
|---|---|
| 后端框架 | Flask 2.3.2, Werkzeug 2.3.6 |
| 数据处理 | Pandas 2.0.3, NumPy |
| 可视化 | Plotly 5.15.0, Chart.js (CDN) |
| 机器学习 | scikit-learn (IsolationForest, One-Class SVM, LOF) |
| 实时通信 | Server-Sent Events (SSE) |
| 前端 | Jinja2, 自定义 CSS, 原生 JavaScript |
| 容器化 | Docker, Docker Compose |
| 测试 | Pytest |
| CI/CD | GitHub Actions |

## 项目结构

```
NSA-CampusNetwork/
├── app.py                  # Flask 入口和路由
├── config.yaml             # 应用配置
├── utils/                  # 核心分析模块
│   ├── analysis.py         # 流量分析和 Plotly 图表
│   ├── user_profile.py     # 用户画像和标签
│   ├── ai_security.py      # AI 安全审查和 DeepSeek 复核
│   ├── ml_anomaly.py       # IsolationForest 异常检测
│   ├── realtime.py         # SSE 回放引擎
│   └── ...
├── templates/              # Jinja2 模板
│   ├── index.html          # 首页
│   ├── dashboard.html      # 安全仪表板
│   └── realtime.html       # 实时大屏
├── static/                 # 静态文件
├── data/                   # 数据存储
├── tests/                  # 测试套件
└── docs/                   # 文档
```

## 配置方式

支持三种配置机制（优先级由高到低）：

1. **环境变量** — 覆盖其他所有来源
2. **`config.yaml`** — 项目根目录的 YAML 配置文件
3. **应用默认值** — 硬编码在 `app.py` 中

### 环境变量

复制 `.env.example` 为 `.env` 并修改：

```bash
cp .env.example .env
```

| 变量 | 默认值 | 说明 |
|---|---|---|
| `FLASK_SECRET_KEY` | `nsa-campus-network-dev-key` | 会话签名密钥 |
| `FLASK_HOST` | `0.0.0.0` | 服务器绑定地址 |
| `FLASK_PORT` | `5001` | 服务器端口 |
| `FLASK_DEBUG` | `false` | 调试模式 |
| `DEEPSEEK_API_KEY` | — | DeepSeek API 密钥（可选） |

## CSV 格式要求

上传的 CSV 文件需包含以下列：

```
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user
```

| 列名 | 说明 | 示例 |
|---|---|---|
| timestamp | 时间戳 | `2025-12-01 08:00:15` |
| src_ip | 源 IP | `192.168.1.100` |
| dst_ip | 目标 IP | `8.8.8.8` |
| src_port | 源端口 | `52341` |
| dst_port | 目标端口 | `53` |
| protocol | 协议 | `TCP/UDP/QUIC` |
| bytes | 字节数 | `256` |
| app_category | 应用类别 | `DNS/Social Media/Video Streaming` |
| user | 用户标识 | `student_001` |

## API 接口

| 路由 | 方法 | 说明 |
|---|---|---|
| `/` | GET | 首页 |
| `/dashboard` | GET | 安全仪表板 |
| `/realtime` | GET | 实时大屏 |
| `/upload` | POST | 上传 CSV |
| `/api/stats` | GET | 基础统计 JSON |
| `/api/dashboard_data` | GET | 仪表板完整数据 |
| `/api/user_profiles` | GET | 用户画像数据 |
| `/api/ai_security` | GET | AI 安全审查报告 |
| `/api/ai_security/deepseek` | POST | DeepSeek 复核 |
| `/api/ml_anomaly` | GET | ML 异常检测结果 |
| `/api/ml_anomaly/refresh` | POST | 重新运行 ML 检测 |
| `/api/realtime/start` | POST | 启动流量回放 |
| `/api/realtime/stop` | POST | 停止流量回放 |
| `/api/realtime/rate` | POST | 调整回放速率 |
| `/api/realtime/status` | GET | 回放状态查询 |
| `/api/realtime/stream` | GET | SSE 实时事件流 |

## 贡献指南

欢迎贡献代码！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解行为准则和提交 PR 的流程。

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件。

---

**最后更新**：2026 年 6 月 1 日
