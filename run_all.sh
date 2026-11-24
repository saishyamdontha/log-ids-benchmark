#!/usr/bin/env bash
# Rebuild every result in results/ from data/russellmitchell.zip (Zenodo record 5789064).
set -euo pipefail
cd "$(dirname "$0")"
ZIP=data/russellmitchell.zip
HOST=intranet_server
APACHE=data/gather/$HOST/logs/apache2/intranet.smith.russellmitchell.com-access.log
[ -f "$ZIP" ] || { echo "missing $ZIP: download russellmitchell.zip from Zenodo 5789064"; exit 1; }
mkdir -p results

echo "[1/5] extract only the logs used (skips files already there)"
unzip -nq "$ZIP" "*/$HOST/logs/apache2/intranet.smith.russellmitchell.com-access.log.*" \
                 "*/$HOST/logs/*audit.log*" "*/$HOST/logs/*auth.log*" -d data || true

labels_arg() { local l="${1/gather/labels}"; [ -f "$l" ] && echo "--labels $l" || true; }

echo "[2/5] parse web logs"
for f in "$APACHE".[1-4]; do
  python src/parse_web.py --log "$f" $(labels_arg "$f") --out "results/web_access_${f##*.}.parquet"
done

echo "[3/5] parse host logs"
audit=$(find data/gather/$HOST -name 'audit.log' | head -1)
python src/parse_host.py --kind audit --log "$audit" $(labels_arg "$audit") --out results/host_audit.parquet
for f in $(find data/gather/$HOST -name 'auth.log*' | sort); do
  case "$f" in *auth.log) n=0 ;; *) n="${f##*.}" ;; esac
  python src/parse_host.py --kind auth --log "$f" $(labels_arg "$f") --out "results/host_auth_${n}.parquet"
done

echo "[4/5] evaluate web detectors"
python src/evaluate_web.py --parsed results/web_access_{1,2,3,4}.parquet --lstm

echo "[5/5] coverage matrix (unseen-event rule, all sources)"
python src/coverage.py --web results/web_access_{1,2,3,4}.parquet \
                       --host results/host_audit.parquet results/host_auth_*.parquet
echo "done: results/web_eval.csv, results/coverage.csv"
