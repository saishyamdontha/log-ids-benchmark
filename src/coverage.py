"""Coverage matrix: which log source sees which attack step (AIT russellmitchell, intranet_server).

One rule, applied the same way to every source:
  ALARM if the event never occurred in that source's TRAINING days (21-22 Jan 2022).
No threshold to tune. Validation (23 Jan) and the normal part of the test day
show the false alarms this rule costs in each source.

Web events are used WITHOUT the user agent (event_noua), as a careful attacker would hide it.

Usage:
  python src/coverage.py --web "results/web_access_*.parquet" \
                         --host results/host_audit.parquet "results/host_auth*.parquet" \
                         --out results/coverage.csv
"""
import argparse, glob
import numpy as np
import pandas as pd

import os
TRAIN_END = pd.Timestamp(os.environ.get("TRAIN_END", "2022-01-23"), tz="UTC")
TEST_START = pd.Timestamp(os.environ.get("TEST_START", "2022-01-24"), tz="UTC")
STEPS = ["service_scan", "dirb", "wpscan", "webshell_upload", "webshell_cmd",
         "attacker_change_user", "escalated_sudo_session", "escalated_sudo_command", "escalated_command"]


def load(patterns, kind_col=None, event_col="event"):
    paths = sorted(p for pat in patterns for p in glob.glob(pat))
    if not paths:
        return []
    df = pd.concat([pd.read_parquet(p) for p in paths], ignore_index=True)
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    df["ev"] = df[event_col]
    df["kind"] = kind_col if kind_col else df["kind"]
    return [g.reset_index(drop=True) for _, g in df.groupby("kind")]


def unseen_alarm(df):
    split = np.where(df.ts < TRAIN_END, "train", np.where(df.ts < TEST_START, "valid", "test"))
    known = set(df.ev[split == "train"])
    alarm = ~df.ev.isin(known).values
    return split, alarm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--web", nargs="+", default=[])
    ap.add_argument("--host", nargs="+", default=[])
    ap.add_argument("--out", default="results/coverage.csv")
    a = ap.parse_args()
    sources = load(a.web, "web_access", "event_noua") + load(a.host)
    matrix, fp = {}, []
    for df in sources:
        name = df.kind.iloc[0]
        split, alarm = unseen_alarm(df)
        atk = df.attack.values
        if (split[atk] != "test").any():
            print(f"WARNING [{name}]: attack lines outside the test day: {(split[atk] != 'test').sum()}")
        col = {}
        for s in STEPS:
            m = (split == "test") & df.attack_labels.str.contains(s).values
            col[s] = f"{alarm[m].sum()}/{m.sum()}" if m.any() else ""
        matrix[name] = col
        for sp in ("valid", "test"):
            m = (split == sp) & ~atk
            fp.append({"source": name, "split": sp, "normal_lines": int(m.sum()),
                       "false_alarms": int(alarm[m].sum()),
                       "fpr_%": round(100 * alarm[m].mean(), 2) if m.any() else np.nan})
        fa = df[(split == "test") & ~atk & alarm]
        if len(fa):
            print(f"[{name}] false alarms on the test day, most common events:")
            for ev, c in fa.ev.value_counts().head(5).items():
                print(f"     x{c:<4d} {str(ev)[:140]}")
        print(f"[{name}] train/valid/test lines: {(split=='train').sum()}/{(split=='valid').sum()}/{(split=='test').sum()}"
              f"   training vocabulary: {len(set(df.ev[split=='train']))} events")
    mat = pd.DataFrame(matrix).reindex(STEPS)
    mat.to_csv(a.out)
    pd.set_option("display.width", 200)
    print("\nCOVERAGE: alarmed lines / attack lines per step (test day). Blank = step not in that log.")
    print(mat.to_string())
    print("\nFALSE ALARMS of the same rule on normal lines:")
    print(pd.DataFrame(fp).to_string(index=False))
    print(f"\nsaved {a.out}")


if __name__ == "__main__":
    main()
