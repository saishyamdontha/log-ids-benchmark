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
   - `lstm`: next-event LSTM (DeepLog-style), early stopping on validation
   - `mix_ngram+lstm`: lambda * P_ngram + (1 - lambda) * P_lstm, lambda chosen on validation
3. `src/evaluate_web.py` prints detection per attack step and test false-positive rate.

## Results (1% false positives on validation; numbers in %)

| Method | user agent | test FPR | dirb | wpscan | service_scan | webshell upload | webshell cmd |
|---|---|---|---|---|---|---|---|
| volume_5min* | - | 0.5 | 100 | 100 | 100 | 100* | 100 |
| rarity | with | 1.8 | 100 | 100 | 100 | 100 | 100 |
| rarity | **without** | **0.2** | 100 | 99.9 | 50 | **0** | 100 |
| ngram_lm | without | 1.2 | 0 | 0 | 16.7 | 0 | 3.1 |
| hybrid_unseen+ngram | without | 1.3 | 100 | 99.9 | 50 | 0 | 100 |
| lstm | without | 1.7 | 100 | 99.9 | 50 | 0 | 100 |
| mix n-gram+LSTM (lambda 0.2) | without | 1.0 | 100 | 99.9 | 50 | 0 | 100 |

\* window artefact: quiet steps share a 5-minute window with the scans.

**Findings**
- A frequency baseline detects every scan and webshell command at 0.2% false alarms,
  even without the user agent.
- Adding sequence order (n-gram) adds false alarms and catches nothing more. Browsers
  load page assets in parallel, so request order is partly random in normal traffic.
- The plain n-gram fails: after the first new request, a stream of new requests stops
  looking surprising (first dirb request 18.1 bits, the rest 11.1, just under the
  11.4-bit threshold).
- An interpolated n-gram + LSTM model (mixing weight chosen on normal validation,
  lambda = 0.2) has fewer false alarms than either part alone (1.0% vs 1.2% and 1.7%),
  but more than the frequency baseline (0.2%). The test day has about 605 normal lines,
  so these rates are about 1 vs 6 false alarms.
- With the user agent, the n-gram, LSTM and mix all miss the scans unless an
  "unseen event = alarm" rule is added.
- The webshell upload (3 requests) is indistinguishable from normal users once the
  user agent is hidden. The access log alone cannot detect it.


## Coverage: which log sees which attack step

One rule for every source: **alarm on any event never seen in that log's training days**
(21-22 Jan). Web events without the user agent. Test day 24 Jan; alarmed / labelled lines.

| Attack step | web access | audit | auth |
|---|---|---|---|
| service scan | 6/12 | | |
| dirb | 4461/4462 | | |
| wpscan | 3183/3186 | | |
| **webshell upload** | **0/3** | | |
| webshell commands | 32/32 | | |
| su to another user | | 4/4 | 4/4 |
| sudo session | | | 3/3 |
| sudo commands (`cat /etc/shadow`) | | 5/5 | 5/5 |

False alarms of the same rule on normal lines:

| Source | 23 Jan (valid) | 24 Jan (test) |
|---|---|---|
| web access | 0 / 831 | 1 / 605 |
| audit | 0 / 576 | 0 / 556 |
| auth | 1 / 158 | 1 / 149 |

**Findings**
- Each log covers a different part of the attack: the web log the break-in, the audit
  and auth logs the account takeover (`www-data` running `su`, then `sudo cat /etc/shadow`).
  No single log sees the whole attack.
- The webshell upload is the one step no log on this host recorded once the user agent
  is hidden: the audit rules record logins and sessions, not file writes.
- The attacker used the same IP (172.19.131.174) as a legitimate user on the day before,
  so blocking by IP would not work.
- 2 of the 3 test-day "false alarms" are probably unlabelled attack lines: a webshell
  request from the attacker's IP at 04:37:25, seconds before the `su`, and an sshd
  "no identification string" line at 03:56:47, one second after the service scan
  started. The numbers above are reported as labelled, without correction.

## Limits
One testbed, one host, one attack run; the test day has 605 normal lines, so false-positive
rates are rough. Step labels come from the dataset. Synthetic testbed traffic.

## Next
A second AIT testbed (for example `santos` or `wardbeck`), to check whether these
findings hold on another network and attack run.

## Reproduce
