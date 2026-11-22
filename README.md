# log-ids-benchmark

Which attack steps can a detector find in server logs, at false-alarm rates a
security team could live with? Methods learn **normal** behaviour only and are
scored per attack step, with and without the attacker's user agent.

Follows [syscall-ids-benchmark](https://github.com/saishyamdontha/syscall-ids-benchmark),
where a 3-gram beat an LSTM at 1% false positives on Linux system calls.

## Data
AIT Log Data Set v2.0, testbed **russellmitchell** (Zenodo record 5789064, not included:
download `russellmitchell.zip`, 7.1 GB). Host: `intranet_server` (WordPress),
Apache access logs `intranet.smith.russellmitchell.com-access.log.{4,3,2,1}`.
Labels come from the dataset (`labels/...`), one entry per attack line.

| Split | Time (UTC) | Lines | Attack lines |
|---|---|---|---|
| train | 21-22 Jan 2022 | 2,053 | 0 |
| valid | 23 Jan (thresholds, model order) | 831 | 0 |
| test  | 24 Jan (attack 03:01-04:39, then a normal day) | 8,300 | 7,695 |

Normal traffic uses only 15-18 distinct request types per day (without user agent).

## Method
1. `src/parse_web.py`: each request becomes `METHOD STATUS PATH_SHAPE[?params]`,
   optionally `| user-agent family`. Drain3 was tried first (`src/parse_logs.py`) but
   collapsed method, path and status, leaving mostly the user agent.
2. Detectors score every request; thresholds are set at 1% / 5% false positives on
   normal validation; nothing is tuned on the test day.
   - `volume_5min`: requests per 5-minute window
   - `rarity`: -log frequency in training
   - `ngram_lm`: variable-order n-gram, order chosen on validation (per source IP)
   - `hybrid_unseen+ngram`: unseen event = alarm, n-gram judges known events
3. `src/evaluate_web.py` prints detection per attack step and test false-positive rate.

## Results (1% false positives on validation; numbers in %)

| Method | user agent | test FPR | dirb | wpscan | service_scan | webshell upload | webshell cmd |
|---|---|---|---|---|---|---|---|
| volume_5min* | - | 0.5 | 100 | 100 | 100 | 100* | 100 |
| rarity | with | 1.8 | 100 | 100 | 100 | 100 | 100 |
| rarity | **without** | **0.2** | 100 | 99.9 | 50 | **0** | 100 |
| ngram_lm | without | 1.2 | 0 | 0 | 16.7 | 0 | 3.1 |
| hybrid_unseen+ngram | without | 1.3 | 100 | 99.9 | 50 | 0 | 100 |

\* window artefact: quiet steps share a 5-minute window with the scans.

**Findings**
- A frequency baseline detects every scan and webshell command at 0.2% false alarms,
  even without the user agent.
- Adding sequence order (n-gram) adds false alarms and catches nothing more. Browsers
  load page assets in parallel, so request order is partly random in normal traffic.
- The plain n-gram fails: after the first new request, a stream of new requests stops
  looking surprising (first dirb request 18.1 bits, the rest 11.1, just under the
  11.4-bit threshold).
- The webshell upload (3 requests) is indistinguishable from normal users once the
  user agent is hidden. The access log alone cannot detect it.

## Limits
One host, one attack, one log type; the test day has 605 normal lines, so false-positive
rates are rough. Step labels come from the dataset. Synthetic testbed traffic.

## Next
LSTM and an interpolated n-gram + LSTM model; then the same host's audit log, to see
whether a second source catches the upload.

## Reproduce
