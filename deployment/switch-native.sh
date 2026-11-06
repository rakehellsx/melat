#!/bin/bash
set -euo pipefail
cd /opt/melat
# The old service is frozen only after the native preview passes.
docker compose stop app worker
snapshot_dir=/data/melat/backups/clickhouse-native-migration
mkdir -p "$snapshot_dir"
chmod 700 "$snapshot_dir"
docker compose exec -T db sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump -u root --single-transaction --no-tablespaces netmeta' | gzip > "$snapshot_dir/mysql.sql.gz"
chmod 600 "$snapshot_dir/mysql.sql.gz"
gzip -t "$snapshot_dir/mysql.sql.gz"
python3 /opt/melat-native/deployment/export-legacy-runner.py "$snapshot_dir"
cd /opt/melat-native
MELAT_ENV_FILE=/etc/melat/melat.env PYTHONPATH=/opt/melat-native .venv/bin/python deployment/import-snapshot.py "$snapshot_dir"
systemctl enable --now melat-web melat-worker
# Keep the frozen MySQL volume and source backup for rollback. Disable automatic restarts.
docker update --restart=no melat-app-1 melat-worker-1 melat-db-1
docker stop melat-db-1
printf 'Native services started; legacy containers stopped and retained for rollback.\n'
