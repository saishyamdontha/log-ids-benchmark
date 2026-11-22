"""Evaluate detectors on parsed Apache access logs (AIT russellmitchell, intranet_server).

Split by time, never randomly:
  train : before 2022-01-23 00:00 UTC   (normal only)
  valid : 2022-01-23 (normal only)      -> choose n-gram order and thresholds here
  test  : from 2022-01-24 00:00 UTC     (attack night + normal day after)

Every method gives each request (log line) a score. The threshold is set so that
1% or 5% of NORMAL validation lines would raise an alarm. Then, on the test day:
  - detection per attack step = share of that step's lines above the threshold
  - false-positive rate       = share of normal test lines above the threshold

Methods:
  volume  : requests in the line's 5-minute window (a window method: a quiet step is
            "detected" if it shares a window with a loud one, so read it with care)
  rarity  : -log frequency of the event in training (unseen events score highest)
  ngram   : surprisal of the event given the same IP's previous events
            (variable-order n-gram LM, order chosen on validation)
Each method runs on events WITH and WITHOUT the user agent.

Usage:  python src/evaluate_web.py --parsed results/web_access_*.parquet --out results/web_eval.csv
"""
import argparse, glob, math, sys
from collections import Counter
import numpy as np
import pandas as pd

sys.path.insert(0, "src")
from ngram_lm import NgramLM, choose_order

TRAIN_END = pd.Timestamp("2022-01-23", tz="UTC")
TEST_START = pd.Timestamp("2022-01-24", tz="UTC")
STEPS = ["dirb", "wpscan", "service_scan", "webshell_upload", "webshell_cmd", "escalate"]
FPRS = [0.01, 0.05]


def load(paths):
    df = pd.concat([pd.read_parquet(p) for p in paths], ignore_index=True)
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    df = df.sort_values(["ts", "source", "line"], kind="stable").reset_index(drop=True)
    df["split"] = np.where(df.ts < TRAIN_END, "train", np.where(df.ts < TEST_START, "valid", "test"))
    return df


def score_volume(df, minutes=5):
    win = df.ts.dt.floor(f"{minutes}min")
    return win.map(win.value_counts()).astype(float).values


def score_rarity(df, col):
    train = df.loc[df.split == "train", col]
    counts, n = Counter(train), len(train)
    v = len(counts) + 1
    return np.array([-math.log((counts.get(e, 0) + 1) / (n + v)) for e in df[col]])


def unk_map(df, col, min_count=2):
    """Events seen fewer than min_count times in TRAINING become <UNK>."""
    counts = Counter(df.loc[df.split == "train", col])
    keep = {e for e, c in counts.items() if c >= min_count}
    return df[col].where(df[col].isin(keep), "<UNK>")


def score_ngram(df, col, verbose=False):
    df = df.assign(_tok=unk_map(df, col))
    col = "_tok"
    seqs = {sp: [g[col].tolist() for _, g in df[df.split == sp].groupby("ip", sort=False)]
            for sp in ("train", "valid")}
    best, table = choose_order(seqs["train"], seqs["valid"], verbose=verbose)
    lm = NgramLM(max_n=best).fit(seqs["train"])
    scores = np.zeros(len(df))
    for _, g in df.groupby("ip", sort=False):        # each IP's requests, in time order
        scores[g.index.values] = lm.surprisals(g[col].tolist())
    return scores, best


def ngram_probs(df, col):
    """Per-event n-gram probabilities (order chosen on validation)."""
    seqs = {sp: [g[col].tolist() for _, g in df[df.split == sp].groupby("ip", sort=False)]
            for sp in ("train", "valid")}
    best, _ = choose_order(seqs["train"], seqs["valid"], verbose=False)
    lm = NgramLM(max_n=best).fit(seqs["train"])
    p = np.zeros(len(df))
    for _, g in df.groupby("ip", sort=False):
        seq = g[col].tolist()
        p[g.index.values] = [lm.prob(t, seq[max(0, i - best + 1):i]) for i, t in enumerate(seq)]
    return p, best


def lstm_probs(df, col, verbose=False):
    from lstm_lm import LSTMLM
    seqs = {sp: [g[col].tolist() for _, g in df[df.split == sp].groupby("ip", sort=False)]
            for sp in ("train", "valid")}
    lm = LSTMLM().fit(seqs["train"], seqs["valid"], verbose=verbose)
    p = np.zeros(len(df))
    for _, g in df.groupby("ip", sort=False):
        p[g.index.values] = lm.probs(g[col].tolist())
    return p


def choose_lambda(df, p_ng, p_ls, grid=np.linspace(0, 1, 11)):
    """Pick the mixing weight with the lowest surprisal on NORMAL validation events."""
    v = ((df.split == "valid") & ~df.attack).values
    bits = {float(l): float(np.mean(-np.log2(l * p_ng[v] + (1 - l) * p_ls[v] + 1e-300))) for l in grid}
    return min(bits, key=bits.get), bits


def threshold(valid_normal_scores, fpr):
    return float(np.quantile(valid_normal_scores, 1 - fpr))


def evaluate(df, scores, method, variant, extra=""):
    rows = []
    vn = scores[(df.split == "valid").values & ~df.attack.values]
    test = (df.split == "test").values
    for fpr in FPRS:
        thr = threshold(vn, fpr)
        alarm = scores > thr                          # strictly above: ties at the threshold do not alarm
        r = {"method": method, "variant": variant, "target_fpr": fpr, "note": extra,
             "valid_fpr": float((vn > thr).mean()),
             "test_fpr": float(alarm[test & ~df.attack.values].mean()) if (test & ~df.attack.values).any() else np.nan,
             "attack_recall": float(alarm[test & df.attack.values].mean()) if (test & df.attack.values).any() else np.nan}
        for s in STEPS:
            m = test & df.attack_labels.str.contains(s).values
            r[s] = float(alarm[m].mean()) if m.any() else np.nan
        rows.append(r)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parsed", nargs="+", required=True)
    ap.add_argument("--out", default="results/web_eval.csv")
    ap.add_argument("--lstm", action="store_true", help="also run the LSTM, the n-gram+LSTM mix and its hybrid")
    a = ap.parse_args()
    paths = sorted(p for pat in a.parsed for p in glob.glob(pat))
    df = load(paths)
    print("lines per split:", df.split.value_counts().to_dict(),
          "| attack lines in train/valid (must be 0):",
          int(df[(df.split != "test") & df.attack].shape[0]))

    rows = evaluate(df, score_volume(df), "volume_5min", "-")
    for variant, col in (("with_ua", "event"), ("no_ua", "event_noua")):
        rows += evaluate(df, score_rarity(df, col), "rarity", variant)
        s, n = score_ngram(df, col)
        rows += evaluate(df, s, "ngram_lm", variant, f"max_n={n}")
        # DeepLog-style hybrid: an event never seen in training is an alarm on its own;
        # the n-gram only judges known events (their order).
        known = set(df.loc[df.split == "train", col])
        h = s.copy()
        h[~df[col].isin(known).values] = 1e6
        rows += evaluate(df, h, "hybrid_unseen+ngram", variant, f"max_n={n}")
        if a.lstm:
            pn, n_ord = ngram_probs(df, col)
            pl = lstm_probs(df, col, verbose=False)
            lam, _ = choose_lambda(df, pn, pl)
            mix = -np.log2(lam * pn + (1 - lam) * pl + 1e-300)
            rows += evaluate(df, -np.log2(pl + 1e-300), "lstm", variant)
            rows += evaluate(df, mix, "mix_ngram+lstm", variant, f"lambda={lam:.1f}, max_n={n_ord}")
            known = set(df.loc[df.split == "train", col])
            mh = mix.copy(); mh[~df[col].isin(known).values] = 1e6
            rows += evaluate(df, mh, "hybrid_unseen+mix", variant, f"lambda={lam:.1f}")
            print(f"[{variant}] mix weight chosen on normal validation: lambda={lam:.1f} (1 = n-gram only, 0 = LSTM only)")
    res = pd.DataFrame(rows)
    res.to_csv(a.out, index=False)

    pd.set_option("display.width", 200)
    show = res.copy()
    for c in ["valid_fpr", "test_fpr", "attack_recall"] + STEPS:
        show[c] = (show[c] * 100).round(1)
    print("\nAll numbers in %. Step columns = share of that step's lines that raised an alarm.")
    for fpr in FPRS:
        print(f"\n=== threshold set for {int(fpr*100)}% false positives on normal validation ===")
        print(show[show.target_fpr == fpr].drop(columns="target_fpr").to_string(index=False))
    print(f"\nsaved {a.out}")


if __name__ == "__main__":
    main()
