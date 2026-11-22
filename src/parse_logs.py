"""Parse one AIT log file into templates, timestamps and attack labels.

Usage:
  python src/parse_logs.py --log data/gather/<host>/logs/<path> \
                           --labels data/labels/<host>/logs/<path> \
                           --year 2022 --out results/parsed_<name>.parquet

Labels: AIT label files have one JSON object per labelled line:
  {"line": <1-based line number>, "labels": [...], "rules": {...}}
Lines without an entry are normal.
"""
import argparse, json, os, re
from datetime import datetime, timezone
import pandas as pd
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.masking import MaskingInstruction

APACHE_TS = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]")
SYSLOG_TS = re.compile(r"^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})")
ISO_TS = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
AUDIT_TS = re.compile(r"msg=audit\((\d+)\.\d+:")


def parse_ts(line, year):
    m = APACHE_TS.search(line)
    if m:
        return datetime.strptime(m.group(1) + " " + m.group(2), "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    m = AUDIT_TS.search(line)
    if m:
        return datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc)
    m = ISO_TS.search(line)
    if m:
        return datetime.fromisoformat(m.group(1).replace(" ", "T")).replace(tzinfo=timezone.utc)
    m = SYSLOG_TS.match(line)
    if m:
        return datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    return None


HTTP_STATUS = re.compile(r'" (\d{3}) ')


def strip_ts(line):
    """Remove the timestamp so it does not become part of the template,
    and keep HTTP status codes (S200, S404) so masking does not hide them."""
    for rx in (APACHE_TS, AUDIT_TS, ISO_TS, SYSLOG_TS):
        line = rx.sub(" ", line, count=1)
    line = HTTP_STATUS.sub(lambda m: f'" S{m.group(1)} ', line)
    return line.strip()


def make_miner():
    cfg = TemplateMinerConfig()
    cfg.drain_sim_th = 0.5
    cfg.drain_depth = 4
    cfg.masking_instructions = [
        MaskingInstruction(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "IP"),
        MaskingInstruction(r"\b[0-9a-fA-F]{8,}\b", "HEX"),
        MaskingInstruction(r"(?<![A-Za-z0-9.])-?\d+(?:\.\d+)?(?![A-Za-z0-9])", "NUM"),
    ]
    cfg.parametrize_numeric_tokens = True
    return TemplateMiner(config=cfg)


def load_labels(path):
    labels = {}
    if path and os.path.exists(path):
        with open(path) as f:
            for raw in f:
                raw = raw.strip()
                if raw:
                    obj = json.loads(raw)
                    labels[int(obj["line"])] = obj.get("labels", [])
    return labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--labels")
    ap.add_argument("--year", type=int, default=2022)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    labels = load_labels(a.labels)
    miner = make_miner()
    rows, no_ts = [], 0
    with open(a.log, errors="replace") as f:
        for n, line in enumerate(f, start=1):        # AIT line numbers start at 1
            line = line.rstrip("\n")
            if not line:
                continue
            ts = parse_ts(line, a.year)
            if ts is None:
                no_ts += 1
                continue
            res = miner.add_log_message(strip_ts(line))
            lab = labels.get(n, [])
            rows.append({"line": n, "ts": ts, "template_id": res["cluster_id"],
                         "attack": bool(lab), "attack_labels": "|".join(lab)})

    df = pd.DataFrame(rows)
    templates = {c.cluster_id: c.get_template() for c in miner.drain.clusters}
    df["template"] = df["template_id"].map(templates)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    df.to_parquet(a.out, index=False)

    print(f"lines parsed: {len(df)}   without timestamp (skipped): {no_ts}")
    print(f"templates: {len(templates)}   attack lines: {int(df['attack'].sum())}   label entries in file: {len(labels)}")
    if len(df):
        print(f"time range: {df['ts'].min()}  ->  {df['ts'].max()}")
    unmatched = set(labels) - set(df["line"])
    if unmatched:
        print(f"WARNING: {len(unmatched)} labelled lines were not parsed (no timestamp?)")
    print("\nmost common templates:")
    print(df["template"].value_counts().head(8).to_string())
    if df["attack"].any():
        print("\nattack labels:")
        print(df.loc[df["attack"], "attack_labels"].value_counts().head(10).to_string())


if __name__ == "__main__":
    main()
