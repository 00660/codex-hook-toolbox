#!/system/bin/sh
set -eu

DATABASE=/data/adb/.vndcfg.db
PACKAGE_NAME=${1:-com.codex.hooktoolbox}
UID_VALUE=$(cmd package list packages -U "$PACKAGE_NAME" 2>/dev/null \
    | sed -n 's/.* uid:\([0-9][0-9]*\).*/\1/p' | head -n1)
[ -n "$UID_VALUE" ] || { echo "未安装 $PACKAGE_NAME" >&2; exit 2; }

BACKUP=/data/adb/.vndcfg.db.before-codex-hook-toolbox
if [ ! -f "$BACKUP" ]; then
    cp -p "$DATABASE" "$BACKUP"
    chcon --reference="$DATABASE" "$BACKUP" 2>/dev/null || true
fi

chmod 0600 "$DATABASE"
sqlite3 "$DATABASE" "BEGIN; INSERT OR REPLACE INTO policies(uid,policy,until,logging,notification) VALUES($UID_VALUE,2,0,1,0); COMMIT;"
sqlite3 "$DATABASE" "SELECT uid,policy,until,logging,notification FROM policies WHERE uid=$UID_VALUE;"
chmod 0000 "$DATABASE"
