#!/bin/bash
# Запускать через cron раз в сутки: 0 3 * * * /path/to/backup.sh
set -e

BACKUP_DIR="./backups"
mkdir -p "$BACKUP_DIR"
DATE=$(date +%Y-%m-%d_%H-%M)
FILE="$BACKUP_DIR/whisper_$DATE.sql"

if [ -z "$DATABASE_URL" ]; then
  echo "DATABASE_URL не задан"
  exit 1
fi

pg_dump "$DATABASE_URL" > "$FILE"
gzip "$FILE"

# Оставляем только 7 последних бэкапов
ls -t "$BACKUP_DIR"/*.gz | tail -n +8 | xargs -r rm

echo "Бэкап сохранён: $FILE.gz"