# 网络安全元数据建模分析平台

基于会话元数据的网络安全建模分析原型系统。

## 功能模块

| 模块 | 说明 |
| --- | --- |
| 态势总览 | 会话量、告警量、威胁分布、协议/地区统计 |
| 元数据建模 | 176 个建模字段（五元组、会话流统计、DNS/HTTP/TLS 等 10 大类），五步可视化建模过程，模型列表与命中会话下钻 |
| 会话检索 | 全量会话元数据检索，单会话 176 字段明细 |
| 数据接入 | 上传 pcap 抓包文件，自动解析并按 NetFlow 风格切分会话入库 |
| 行为关联分析 | 14 条内置行为分析规则（入侵攻击、C&C 与恶意通信、数据安全、异常行为基线 4 大类） |
| 告警中心 | 告警列表、证据查看、确认/忽略处置 |

## 技术栈

- **前端**：React 19 + TypeScript + Vite + Tailwind CSS + TanStack Query
- **后端与分析引擎**：Python 3.10+ / FastAPI + PyMySQL（REST API、14 条行为关联分析引擎、模型执行引擎、纯 Python pcap 解析器，见 `backend/`）
- **数据库**：MySQL 8.0+ / TiDB 6.0+
- `api/boot.ts`：平台部署用 Node 启动器（拉起 Python 后端并代理流量）

## 快速开始

```bash
pip install -r requirements.txt   # 安装 Python 依赖
npm install && npm run build      # 构建前端
mysql -u root -p netmeta < db/init.sql   # 初始化数据库（含演示数据）
cp .env.example .env              # 配置 DATABASE_URL
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 3000
```

访问 http://localhost:3000 。详细步骤见 [安装部署指南.md](安装部署指南.md)，也可用 Docker 一体化部署（见指南第五节）。

## 目录结构

```
backend/    Python 后端（FastAPI 路由、分析引擎、模型引擎、pcap 解析）
api/        平台部署入口（Node 启动器）
src/        React 前端
contracts/  前后端共享契约定义
db/init.sql 数据库初始化脚本（建表 + 演示数据）
Dockerfile  一体化镜像（前端构建 + Python 运行时）
```
