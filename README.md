# log-ids-benchmark

**Question:** which attack steps can a detector find in server logs at false-alarm rates a
security team could live with (1% and 5%), when it learns from **normal** behaviour only?

Follows [syscall-ids-benchmark](https://github.com/saishyamdontha/syscall-ids-benchmark),
where a 3-gram beat an LSTM at 1% false positives on Linux system calls. This project asks
whether that holds on logs.

## Headline
1. **Simple wins again.** A frequency score (`rarity`) catches every detectable web step at
   0.17% test false positives, as well as an n-gram, an LSTM or their mix, and with fewer false alarms.
2. **Language models cannot flag novel events at 1% FP.** With Witten-Bell backoff, a
   never-seen event in a never-seen context gets at most ~log2(N+V) = 11.1 bits of surprise,
   less than a *known* event that breaks a confident context. An explicit
   "unseen event = alarm" rule (DeepLog-style) fixes this.
3. **Web logs see reconnaissance, host logs see privilege escalation, and no log used here
   sees the webshell upload** once the attacker's user agent is removed.

## Data
AIT Log Data Set v2.0, testbed **russellmitchell** (Zenodo record 5789064, not included).
Host `intranet_server` (WordPress): Apache access logs, Linux audit log, auth.log.

| Split | Time (UTC) | Web lines | Attack lines |
|---|---|---|---|
| train | 21-22 Jan 2022 | 2,053 | 0 |
| valid | 23 Jan (thresholds, model order, lambda) | 831 | 0 |
| test  | 24 Jan (attack 03:01-04:39, then normal) | 8,300 | 7,695 |

Normal web traffic uses only 18 distinct events (30 with user agent) over the two training days.

## Protocol
- Each request becomes an event `METHOD STATUS PATH_SHAPE`, optionally `| user-agent family`
  (`src/parse_web.py`). Host lines become events in `src/parse_host.py`.
- Detectors are trained on train, thresholds are set at 1% / 5% false positives on **normal
  validation**, and the test day is scored once. Nothing is tuned on test.
- Detection is reported **per attack step**, plus the realised test false-positive rate.
- `with_ua` / `no_ua`: the user agent is attacker-controlled and trivial to fake, so
  **`no_ua` is the honest setting**; `with_ua` shows how much a careless attacker gives away.

Detectors: `volume_5min` (requests per 5 min), `rarity` (-log training frequency),
`ngram_lm` (variable-order Witten-Bell n-gram per source IP, order chosen on validation),
`lstm` (next-event LSTM), `mix` (lambda*n-gram + (1-lambda)*LSTM, lambda chosen on validation),
and `hybrid_unseen+*` (unseen event = alarm, model judges known events).

## Results: web logs, 1% FP target (numbers in %)

**Without user agent (honest)**

| Method | test FPR | dirb | wpscan | service scan | webshell upload | webshell cmd | escalate |
|---|---|---|---|---|---|---|---|
| rarity | **0.17** | 100.0 | 99.9 | 50.0 | **0** | 100 | 100 |
| ngram_lm | 1.16 | 0.04 | 0.03 | 16.7 | 0 | 3.1 | 0 |
| hybrid_unseen+ngram | 1.32 | 100.0 | 99.9 | 50.0 | 0 | 100 | 100 |
| lstm | 1.65 | 100.0 | 99.9 | 50.0 | 0 | 100 | 100 |
| mix (lambda=0.2) | 0.99 | 100.0 | 99.9 | 50.0 | 0 | 100 | 100 |

**With user agent**

| Method | test FPR | dirb | wpscan | service scan | webshell upload | webshell cmd | escalate |
|---|---|---|---|---|---|---|---|
| rarity | 1.82 | 100 | 100 | 100 | 100 | 100 | 100 |
| ngram_lm | 0.50 | 0 | 0 | 8.3 | 0 | 0 | 0 |
| hybrid_unseen+ngram | 0.66 | 100 | 100 | 100 | 100 | 100 | 100 |
| lstm | 1.49 | 0 | 0 | 41.7 | 0 | 0 | 0 |
| mix (lambda=0.4) | 0.83 | 0 | 0 | 50.0 | 0 | 0 | 0 |

At 5% FP every learned detector reaches ~100% on the detectable steps. Full table: `results/web_eval.csv`.
`volume_5min` scores 100% everywhere only because quiet steps share a 5-minute window with the
scans (window artefact); it is not a real detection.

## Results: coverage across log sources
One rule, no threshold: **an event never seen in training is an alarm.**

| Attack step | web access | audit | auth |
|---|---|---|---|
| service_scan | 6/12 | | |
| dirb | 4461/4462 | | |
| wpscan | 3183/3186 | | |
| webshell_upload | **0/3** | | |
| webshell_cmd | 32/32 | | |
| attacker_change_user | | 4/4 | 4/4 |
| escalated_sudo_session | | | 3/3 |
| escalated_sudo_command | | 5/5 | 5/5 |
| escalated_command | | 5/5 | 5/5 |

False alarms of the same rule on the test day: web 0.17%, audit 0.00%, auth 0.67%.

## Error analysis
- **Why `ngram_lm` fails at 1%.** All attack events are unseen in training, so their context is
  unseen too, and `prob()` backs off to the empty context: P ~ 1/(N+V), surprise ~ 11.1 bits.
  The 1% thresholds are 11.4 (no UA) and 14.5 (with UA) bits; the 5% thresholds are 5.3. That
  explains the jump from 0% to 100% detection between 1% and 5% FP.
- **Why the upload is invisible.** Its three requests (`GET /`, `GET /?p`,
  `POST /wp-admin/admin-ajax.php`) occur 318, 154 and 475 times in normal traffic, and the exact
  3-event sequence occurs 19 times. The attacker never logged in, but neither does normal
  admin-ajax traffic in this log (no login POSTs at all), so a "POST without login" rule would
  flag every normal request. Only the `python-requests` user agent separates it.
- **Label gaps.** Some auth.log lines written by the attacker's `su` carry no attack label, so
  part of the auth "false alarms" may be unlabelled attack lines.

## Limits
- One testbed, one host, synthetic traffic; results may not transfer to other AIT testbeds.
- Small normal test sets (605 web lines): one false alarm = 0.17% FPR.
- Thresholds come from a single normal validation day.
- The LSTM's failure at 1% FP **with** user agent is not explained yet.
- DNS logs (where the dataset's DNSteal contaminates training) are not used.

## Reproduce
```bash
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
# put russellmitchell.zip (Zenodo 5789064) in data/
./run_all.sh            # rebuilds results/web_eval.csv and results/coverage.csv
python -m pytest -q
```

## Layout
`src/parse_web.py`, `src/parse_host.py` parsers · `src/ngram_lm.py`, `src/lstm_lm.py` models ·
`src/evaluate_web.py` web evaluation · `src/coverage.py` unseen-event rule across sources ·
`src/parse_logs.py` first Drain3 attempt (dropped: it merged method, path and status).
