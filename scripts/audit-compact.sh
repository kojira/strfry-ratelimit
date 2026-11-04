#!/bin/bash
# Compress finished audit days and expire old ones. Usage: audit-compact.sh <dir> [keep_days=90]
set -u
DIR=${1:?usage: audit-compact.sh <dir> [keep_days]}; KEEP=${2:-90}
cd "$DIR" || exit 1
TODAY=$(date -u +%Y%m%d)
for f in audit-*.tsv; do
  [ -e "$f" ] || continue
  d=${f#audit-}; d=${d%.tsv}
  [ "$d" \< "$TODAY" ] || continue          # today's file is still being written
  gzip -9 -f "$f"
done
find . -maxdepth 1 -name 'audit-*.tsv.gz' -mtime +"$KEEP" -delete
