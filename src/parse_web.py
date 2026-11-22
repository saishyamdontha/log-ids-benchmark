"""Parse an Apache access log into structured web events, with AIT labels.

Instead of Drain3 templates (which collapse method, path and status into <*>
and leave mostly the user agent), each request becomes an event:

  event       = METHOD STATUS PATH_SHAPE[?param names]   + UA family
  event_noua  = the same without the user agent

PATH_SHAPE keeps the first two folders and the file extension:
  /wp-content/uploads/2022/01/shell.php?cmd=id  ->  /wp-content/uploads/*.php?cmd
  /wp-content/plugins/wpdiscuz/assets/x.woff2   ->  /wp-content/plugins/*.woff2
  /admin.php                                    ->  /*.php

Usage:
  python src/parse_web.py --log <access.log> [--labels <label file>] --out results/<name>.parquet
"""
import argparse, json, os, re
from datetime import datetime
from urllib.parse import urlsplit, parse_qsl
import pandas as pd

LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}|-) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')

UA_FAMILIES = [  # first match wins; order matters
    ("wpscan", r"wpscan"), ("python-requests", r"python-requests"), ("curl", r"\bcurl/"),
    ("wget", r"\bwget/"), ("nmap", r"nmap"), ("dirb-msie", r"MSIE \d"), ("apache-internal", r"internal dummy"),
    ("wordpress", r"^WordPress/"), ("headless-chrome", r"HeadlessChrome"), ("firefox", r"Firefox/"),
    ("chrome", r"Chrome/"), ("safari", r"Safari/"), ("empty", r"^-?$"),
]


def ua_family(ua):
    ua = ua or ""
    for name, rx in UA_FAMILIES:
        if re.search(rx, ua, re.I):
            return name
    return "other"


def path_shape(target):
    if target in ("*", "-", ""):
        return target or "-"
    parts = urlsplit(target)
    segs = [s for s in parts.path.split("/") if s]
    ext = ""
    if segs and "." in segs[-1]:
        ext = "." + segs[-1].rsplit(".", 1)[1].lower()[:8]
        segs = segs[:-1]                          # drop the file name, keep its extension
    folders = [re.sub(r"\d+", "N", f) for f in segs[:2]]
    shape = "/" + "/".join(folders)
    if len(segs) > 2 or ext:
        shape = shape.rstrip("/") + "/*" + ext
    keys = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    if keys:
        shape += "?" + "&".join(k[:20] for k in keys[:4])
    return shape


def parse_line(line):
    m = LINE.match(line)
    if not m:
        return None
    req = m.group("req").split()
    method = req[0] if len(req) >= 2 else "-"
    target = req[1] if len(req) >= 2 else "-"
    status = m.group("status")
    shape = path_shape(target)
    fam = ua_family(m.group("ua"))
    ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
    size = m.group("size")
    return {"ts": ts, "ip": m.group("ip"), "method": method, "status": status, "path_shape": shape,
            "ua_family": fam, "bytes": int(size) if size.isdigit() else 0,
            "event_noua": f"{method} {status} {shape}",
            "event": f"{method} {status} {shape} | {fam}"}


def load_labels(path):
    labels = {}
    if path and os.path.exists(path):
        for raw in open(path):
            raw = raw.strip()
            if raw:
                obj = json.loads(raw)
                labels[int(obj["line"])] = obj.get("labels", [])
    return labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--labels")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    labels = load_labels(a.labels)
    rows, bad = [], 0
    for n, line in enumerate(open(a.log, errors="replace"), start=1):
        line = line.rstrip("\n")
        if not line:
            continue
        r = parse_line(line)
        if r is None:
            bad += 1
            continue
        lab = labels.get(n, [])
        r.update({"line": n, "attack": bool(lab), "attack_labels": "|".join(lab), "source": os.path.basename(a.log)})
        rows.append(r)
    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    df.to_parquet(a.out, index=False)
    print(f"lines parsed: {len(df)}   unparsed: {bad}   attack lines: {int(df['attack'].sum()) if len(df) else 0}"
          f"   label entries: {len(labels)}")
    if len(df):
        print(f"time range: {df.ts.min()} -> {df.ts.max()}")
        print(f"distinct events: {df.event.nunique()}   without user agent: {df.event_noua.nunique()}")
        print("\nuser-agent families:\n" + df.ua_family.value_counts().to_string())
        if df.attack.any():
            print("\nfirst events per attack step (without user agent):")
            for lab in ["dirb", "wpscan", "service_scan", "webshell_upload", "webshell_cmd", "escalate"]:
                sub = df[df.attack_labels.str.contains(lab)]
                if len(sub):
                    print(f"  {lab:16s} n={len(sub):5d}  " + "; ".join(sub.event_noua.value_counts().head(3).index))


if __name__ == "__main__":
    main()
