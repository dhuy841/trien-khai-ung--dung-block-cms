#!/bin/sh
set -eu

case "$MYSQL_EXPORTER_PASSWORD" in
  *[!A-Za-z0-9_-]*|'') echo "MYSQL_EXPORTER_PASSWORD must use only letters, digits, underscore or hyphen" >&2; exit 1 ;;
esac

mysql --protocol=socket -uroot -p"$MYSQL_ROOT_PASSWORD" <<SQL
CREATE USER IF NOT EXISTS 'exporter'@'%' IDENTIFIED BY '${MYSQL_EXPORTER_PASSWORD}';
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'%';
FLUSH PRIVILEGES;
SQL
