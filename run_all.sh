#!/usr/bin/env bash
# Rebuild all results for one AIT-LDS v2.0 testbed (Zenodo record 5789064).
#   ./run_all.sh                                                -> russellmitchell, results/
#   TESTBED=santos TRAIN_END=YYYY-MM-DD TEST_START=YYYY-MM-DD ./run_all.sh  -> results/santos/
# Splits: train < TRAIN_END <= valid < TEST_START <= test (UTC).
set -euo pipefail
cd "$(dirname "$0")"
TESTBED=${TESTBED:-russellmitchell}
export TRAIN_END=${TRAIN_END:-2022-01-23} TEST_START=${TEST_START:-2022-01-24}
ZIP=data/$TESTBED.zip; D=data/$TESTBED; HOST=intranet_server
if [ "$TESTBED" = russellmitchell ]; then OUT=results; else OUT=results/$TESTBED; fi
[ -f "$ZIP" ] || { echo "missing $ZIP: download $TESTBED.zip from Zenodo 5789064"; exit 1; }
mkdir -p "$OUT" "$D"
echo "testbed=$TESTBED  train<$TRAIN_END<=valid<$TEST_START<=test  out=$OUT"

echo "[1/6] extract only the logs used (skips files already there)"
unzip -nq "$ZIP" "*/$HOST/logs/apache2/intranet.*-access.log*" \
                 "*/$HOST/logs/*audit.log*" "*/$HOST/logs/*auth.log*" -d "$D" || true

labels_arg() { local l="${1/gather/labels}"; [ -f "$l" ] && echo "--labels $l" || true; }

echo "[2/6] parse web logs"
web=()
for f in "$D"/gather/$HOST/logs/apache2/intranet.*-access.log.[0-9]*; do
  case "$f" in *.gz) continue ;; esac
  o="$OUT/web_access_${f##*.}.parquet"
  python src/parse_web.py --log "$f" $(labels_arg "$f") --out "$o"; web+=("$o")
done

echo "[3/6] parse host logs"
audit=$(find "$D/gather/$HOST" -name 'audit.log' | head -1)
python src/parse_host.py --kind audit --log "$audit" $(labels_arg "$audit") --out "$OUT/host_audit.parquet"
for f in $(find "$D/gather/$HOST" -name 'auth.log*' | sort); do
  case "$f" in *auth.log) n=0 ;; *) n="${f##*.}" ;; esac
  python src/parse_host.py --kind auth --log "$f" $(labels_arg "$f") --out "$OUT/host_auth_${n}.parquet"
done

echo "[4/6] evaluate web detectors"
python src/evaluate_web.py --parsed "${web[@]}" --lstm --out "$OUT/web_eval.csv"
echo "[5/6] window baselines (PCA, Isolation Forest)"
python src/baselines_window.py --parsed "${web[@]}" --out "$OUT/window_baselines.csv"
echo "[6/6] coverage matrix (unseen-event rule, all sources)"
python src/coverage.py --web "${web[@]}" --host "$OUT/host_audit.parquet" "$OUT"/host_auth_*.parquet \
                       --out "$OUT/coverage.csv"
echo "done: $OUT/{web_eval,window_baselines,coverage}.csv"
