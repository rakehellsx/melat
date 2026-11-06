# 原生部署：ClickHouse 22.3.10.22

## 目录和服务

| 项目 | 路径或名称 |
| --- | --- |
| 源码、静态页面、虚拟环境 | `/opt/melat-native` |
| ClickHouse 官方二进制 | `/data/melat/clickhouse-22.3.10.22/usr/bin/clickhouse` |
| ClickHouse 数据 | `/data/melat/clickhouse/data` |
| 运行环境与密码 | `/etc/melat/melat.env`，权限 0640 |
| ClickHouse 用户配置 | `/etc/melat/clickhouse-users.xml` |
| 后台文件 | `/data/melat/native-imports` |
| 锁与 ID 状态 | `/data/melat/native-state` |
| systemd 服务 | `clickhouse-server`、`melat-web`、`melat-worker` |
| 页面 | `http://服务器IP:3000` |

ClickHouse 仅监听 127.0.0.1 的 8123/9000，不对外公开数据库端口。Web 和 worker 使用专门的 melat 系统账号，ClickHouse 使用 clickhouse 系统账号。此部署不依赖 Docker 或 MySQL。

## 安装

Ubuntu 24.04、Python 3.12、Node.js 20（只在构建前端时使用）、TShark。建议 8 GiB 内存，并为抓包、临时聚合和 ClickHouse 数据预留足够磁盘空间。

从官方包源获取固定版本：

```bash
curl -fL https://packages.clickhouse.com/deb/pool/main/c/clickhouse-common-static/clickhouse-common-static_22.3.10.22_amd64.deb -o clickhouse-common-static_22.3.10.22_amd64.deb
dpkg-deb -f clickhouse-common-static_22.3.10.22_amd64.deb Package Version Architecture
sudo mkdir -p /data/melat/clickhouse-22.3.10.22
sudo dpkg-deb -x clickhouse-common-static_22.3.10.22_amd64.deb /data/melat/clickhouse-22.3.10.22
```

将项目安装到 `/opt/melat-native`：

```bash
cd /opt/melat-native
sudo apt-get install -y python3-venv tshark
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
npm ci --include=dev
npm run build
sudo python3 deployment/prepare-native.py
sudo chown -R root:melat /opt/melat-native
sudo chmod -R g+rX /opt/melat-native
sudo systemctl enable --now melat-web melat-worker
```

`prepare-native.py` 生成随机密码、数据库用户配置、目录权限和 systemd 单元；重复运行保留现有密码。首次启动创建空库，不导入样例业务记录。版本不匹配时程序明确拒绝启动。

## 旧数据迁移

先用独立测试实例验证，再停止旧 Web / worker，保留 MySQL 运行以完成一致快照导出。迁移脚本只接受空 ClickHouse 目标表，导入后逐行哈希核对六张表，保留 ID、模型、任务、时间和元数据。`export-mysql.py` 在旧 Python 环境运行，`import-snapshot.py` 在新环境运行；迁移驱动依赖单独列在 `deployment/requirements-migration.txt`。

本服务器执行过的迁移快照、MySQL 备份和核对结果位于 `/data/melat/backups/clickhouse-native-migration/`。不要再次向非空表导入，否则会造成重复；脚本会主动拒绝。

## 运维

```bash
systemctl status clickhouse-server melat-web melat-worker
journalctl -u melat-web -n 100 --no-pager
journalctl -u melat-worker -n 100 --no-pager
curl -f http://127.0.0.1:3000/api/health
```

ClickHouse 错误日志：`/data/melat/clickhouse/log/error.log`。数据库配置限制内存，后台解析独立限制为 3 GiB。上传上限为 2,147,483,648 字节；Web、worker 必须共用 PCAP_WORK_DIR 和 MELAT_STATE_DIR，禁止分别配置多个锁目录。

更新/删除同步等待 ClickHouse mutation 完成。它不提供跨表事务；失败导入通过批次补偿清理恢复，会话删除和批次统计是串行但跨表分步更新。对批量删除或删除全部的确认保持不变。

## 回退

新服务切换前的源码、数据库和旧容器均保留。先停止新 Web / worker，并处理切换后产生的新数据，再启用旧版本；旧快照不会自动包含新 ClickHouse 写入。不要在两套应用同时对外写入时回退。此目录保留的迁移工具只用于维护，不作为运行时依赖。
