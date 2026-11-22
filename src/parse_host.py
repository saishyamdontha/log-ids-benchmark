"""Parse host logs (Linux audit log, syslog-style auth.log) into events with AIT labels.

audit : event = TYPE exe=<exe> uid=<uid> acct=<account> res=<result>
        (uid and account are kept: "www-data (uid 33) runs su" is the signal)
auth  : event = Drain3 template of the message, with the program name in front;
        user names are kept, numbers, IPs and PIDs are masked.

Usage:
  python src/parse_host.py --kind audit --log <audit.log> [--labels <file>] --out results/host_audit.parquet
  python src/parse_host.py --kind auth  --log <auth.log>  [--labels <file>] --out results/host_auth.parquet --year 2022
"""
import argparse, os, re
from datetime import datetime, timezone
import pandas as pd
from parse_logs import load_labels, make_miner, SYSLOG_TS

AUDIT_TS = re.compile(r"msg=audit\((\d+)\.(\d+):\d+\)")
AUDIT_TYPE = re.compile(r"^type=(\w+)")
FIELD = {k: re.compile(rf'\b{k}="?([^"\s\']+)') for k in ("exe", "uid", "acct", "res", "op")}
SYSLOG = re.compile(r"^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([\w\-/.]+)(?:\[\d+\])?: (.*)$")


def audit_event(line):
    m, t = AUDIT_TS.search(line), AUDIT_TYPE.match(line)
    if not m or not t:
        return None
    ts = datetime.fromtimestamp(int(m.group(1)) + int(m.group(2)) / 1000, tz=timezone.utc)
    f = {k: (rx.search(line).group(1) if rx.search(line) else "-") for k, rx in FIELD.items()}
    ev = f"{t.group(1)} op={f['op']} exe={f['exe']} uid={f['uid']} acct={f['acct']} res={f['res']}"
    return ts, ev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=["audit", "auth"], required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--labels")
    ap.add_argument("--year", type=int, default=2022)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    labels = load_labels(a.labels)
    miner = make_miner() if a.kind == "auth" else None
    rows, bad = [], 0
    for n, line in enumerate(open(a.log, errors="replace"), start=1):
        line = line.rstrip("\n")
        if not line:
            continue
        if a.kind == "audit":
            r = audit_event(line)
            if r is None:
                bad += 1
                continue
            ts, ev = r
        else:
            m = SYSLOG.match(line)
            if not m:
                bad += 1
                continue
            ts = datetime.strptime(f"{a.year} {m.group(1)}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            prog = m.group(3)
            msg = re.sub(r"\b(e?uid)=(\d+)", r"\1\2", m.group(4))   # keep uids: uid33 = www-data
            res = miner.add_log_message(f"{prog}: {msg}")
            ev = res["cluster_id"]                      # resolved to the final template below
        lab = labels.get(n, [])
        rows.append({"line": n, "ts": ts, "event": ev, "attack": bool(lab),
                     "attack_labels": "|".join(lab), "source": os.path.basename(a.log), "kind": a.kind})
    df = pd.DataFrame(rows)
    if a.kind == "auth" and len(df):
        tpl = {c.cluster_id: c.get_template() for c in miner.drain.clusters}
        df["event"] = df["event"].map(tpl)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    df.to_parquet(a.out, index=False)
    print(f"[{a.kind}] lines: {len(df)}  unparsed: {bad}  attack lines: {int(df.attack.sum()) if len(df) else 0}"
          f"  label entries: {len(labels)}  distinct events: {df.event.nunique() if len(df) else 0}")
    if len(df):
        print(f"time range: {df.ts.min()} -> {df.ts.max()}")
        for ev, c in df[df.attack].event.value_counts().head(8).items():
            print(f"  attack event x{c}: {ev[:150]}")


if __name__ == "__main__":
    main()
