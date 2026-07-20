#!/usr/bin/env bash
# Regenerates src-tauri/src/net/oui_db.tsv (MAC prefix -> vendor) from the
# Wireshark manufacturer database. Run occasionally to refresh vendor coverage.
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$DIR/src-tauri/src/net/oui_db.tsv"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "Downloading Wireshark manuf database…"
curl -sSL -A "Mozilla/5.0" \
  https://www.wireshark.org/download/automated/data/manuf -o "$TMP"

python3 - "$TMP" "$OUT" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
out = {}
with open(src, encoding="utf-8", errors="replace") as f:
    for line in f:
        if line.startswith("#") or not line.strip():
            continue
        parts = [p.strip() for p in line.split("\t") if p.strip() != ""]
        if len(parts) < 2 or "/" in parts[0]:  # skip MA-M / MA-S long prefixes
            continue
        hexp = parts[0].replace(":", "").replace("-", "").upper()
        if len(hexp) != 6 or any(c not in "0123456789ABCDEF" for c in hexp):
            continue
        vendor = (parts[-1] if len(parts) >= 3 else parts[1]).replace("\t", " ").strip()
        if vendor:
            out[hexp] = vendor[:80]
with open(dst, "w", encoding="utf-8") as w:
    for k in sorted(out):
        w.write(f"{k}\t{out[k]}\n")
print(f"{len(out)} OUI entries -> {dst}")
PY
