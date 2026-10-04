#!/usr/bin/env bash
set -euo pipefail
umask 077

root=/home/ubuntu/sub2api
backup_root="$root/backups/daily"
keyring_root="$root/backups/keyring"
recipient=/etc/sub2api/backup-recipient.pem
keyring_source="${CREDENTIAL_KEYRING_FILE:-/etc/sub2api/upstream-credential-keyring.json}"
keyring_recipient="${CREDENTIAL_KEYRING_RECIPIENT_FILE:-/etc/sub2api/credential-keyring-recipient.pem}"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
work=$(mktemp -d /run/sub2api-backup.XXXXXXXX)
pending="$backup_root/.$stamp.incomplete"
final="$backup_root/$stamp.p7m"
keyring_pending="$keyring_root/.$stamp.keyring.incomplete"
keyring_final="$keyring_root/$stamp.keyring.p7m"
trap 'rm -rf -- "$work"; rm -f -- "$pending" "$keyring_pending"' EXIT

test -r "$recipient"
test -r "$keyring_source"
test -r "$keyring_recipient"
install -d -m 700 "$backup_root"
install -d -m 700 "$keyring_root"

# Keep the credential keyring in a separately encrypted archive. The database
# archive carries only this value-free manifest, so a database backup cannot
# silently become the keyring's custody domain.
openssl cms -encrypt -binary -aes-256-cbc -in "$keyring_source" \
  -out "$keyring_pending" -outform DER "$keyring_recipient"
test -s "$keyring_pending"
chmod 600 "$keyring_pending"
mv -- "$keyring_pending" "$keyring_final"
keyring_hash=$(sha256sum "$keyring_final" | awk '{print $1}')
cat > "$work/keyring-manifest.json" <<EOF
{"format":"sub2api-keyring-manifest-v1","archive":"$(basename "$keyring_final")","sha256":"$keyring_hash","source":"$(basename "$keyring_source")","createdUtc":"$stamp"}
EOF
chmod 600 "$work/keyring-manifest.json"

docker exec sub2api-postgres pg_dump -U sub2api -d sub2api -Fc > "$work/database.dump"
docker run --rm -v "$work:/backup:ro" postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873 pg_restore -l /backup/database.dump > /dev/null

docker exec sub2api-redis redis-cli SAVE > /dev/null
cp "$root/redis_data/dump.rdb" "$work/redis.rdb"
docker run --rm --entrypoint redis-check-rdb -v "$work:/backup:ro" redis@sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0 /backup/redis.rdb > /dev/null

tar -czf "$work/app-state.tgz" --exclude=data/logs -C "$root" .env data
(cd "$work" && sha256sum database.dump redis.rdb app-state.tgz keyring-manifest.json > SHA256SUMS)
tar -czf "$work/payload.tgz" -C "$work" database.dump redis.rdb app-state.tgz keyring-manifest.json SHA256SUMS
openssl cms -encrypt -binary -aes-256-cbc -in "$work/payload.tgz" -out "$pending" -outform DER "$recipient"
test -s "$pending"
chmod 600 "$pending"
mv -- "$pending" "$final"
printf 'Sub2API encrypted backup created: %s\n' "$final"
