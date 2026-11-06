# 网络安全元数据建模分析平台

原生 Python / systemd 部署，数据库为 **ClickHouse 22.3.10.22**，协议解析使用 PyShark / TShark。

功能包括态势总览、数据建模、会话检索、数据导入、关联分析和告警中心。模型构建开放 176 个字段；列表每页 10 条；支持单文件 2 GiB 的 PCAP / PCAPNG 后台导入，以及会话和告警的批量、全部删除。

## 运行

在服务器安装 ClickHouse 22.3.10.22、Python 3.12 与 TShark。Node.js 20 只用于前端构建。

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
npm ci --include=dev
npm run build
cp .env.example .env
# 修改 .env 的 ClickHouse 密码和数据目录
.venv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port 3000
# 另一个进程，与 Web 共用环境变量和本地状态目录
.venv/bin/python -m backend.ingest_worker
```

正式部署使用 `deployment/` 中的 systemd 单元，详细步骤见[安装部署指南](安装部署指南.md)。数据库结构启动时幂等创建；不会自动灌入演示数据。

已有 ClickHouse 的 CentOS 7 服务器使用原生 TCP 连接：`clickhouse+native://用户:URL编码密码@127.0.0.1:9000/netmeta`。`deployment/install-existing-clickhouse.py` 配置应用独立服务，保留既有 ClickHouse 配置；离线 Python 依赖版本见 `deployment/requirements-centos7.lock`。六个初始行为模型通过 `deployment/seed-models.py` 显式初始化。

## 存储与一致性

会话、模型、告警、导入任务均保存在 ClickHouse。JSON 元数据存为 String，时长使用 Int64 毫秒。批量导入每次最多 5,000 行，避免过多小数据 part。更新与删除使用 22.3 支持的同步 mutation，接口返回前等待完成。

此版本部署在单台服务器：Web 和 worker 共用 `MELAT_STATE_DIR`，通过文件锁串行化导入及删除，数字 ID 由持久化的单机序列生成。ClickHouse 没有 MySQL 的跨表事务；导入失败或 worker 重启时按已记录的批次 ID 执行可重复的补偿清理。多个服务器同时写入需要另外设计分布式锁和 ID 服务。

后台解析为磁盘聚合，包含 IPv4/IPv6、VLAN、TCP 重组、DNS、HTTP、TLS 字段。前后向超过 30 秒的时间间隔拆分会话，小范围乱序可合并。异常小数秒规范化不修改用户原包，页面显示修正数量。

## 检查

```bash
.venv/bin/python -m unittest discover -s tests -p test_pcap_parser.py -v
# 独立测试库必须为 netmeta_native_test，禁止指向正式库执行删除测试
MELAT_ENV_FILE=/etc/melat/melat.env PYTHONPATH=. .venv/bin/python deployment/run-test-native.py
curl -f http://127.0.0.1:3000/api/health
```

`deployment/export-mysql.py` 仅用于从旧版本一次性导出历史数据，MySQL 驱动列在单独的迁移依赖文件中，不是应用运行依赖。旧部署及备份留在服务器供回退，不作为当前服务运行。
