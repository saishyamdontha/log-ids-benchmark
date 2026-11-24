"""Standard log-anomaly baselines (PCA residual, Isolation Forest) on per-IP 1-minute windows.

Each source IP's requests are cut into 1-minute windows. A window is a log1p count vector
over the events seen in TRAINING, optionally plus one column counting unseen events.
Models are fit on training windows only. Every event gets its window's score. Thresholds
are set at 1% / 5% false positives on normal validation events (same protocol as
evaluate_web.py); the test day is scored once.

Usage: python src/baselines_window.py --parsed results/web_access_*.parquet
"""
import argparse
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

STEPS = ["dirb", "wpscan", "service_scan", "webshell_upload", "webshell_cmd", "escalate"]
UNSEEN = "__UNSEEN__"


def split_of(ts):
    d = ts.dt.strftime("%Y-%m-%d")
    return np.where(d < "2022-01-23", "train", np.where(d == "2022-01-23", "valid", "test"))


def window_matrix(df, col, vocab, unseen_col):
    ev = df[col].where(df[col].isin(vocab), UNSEEN)
    ct = pd.crosstab(df.wid, ev)                          # rows = integer window ids
    cols = list(vocab) + ([UNSEEN] if unseen_col else [])
    X = ct.reindex(columns=cols, fill_value=0)
    return np.log1p(X.values.astype(float)), X.index


def scores(method, Xtr, X):
    sc = StandardScaler().fit(Xtr)
    Xtr, X = sc.transform(Xtr), sc.transform(X)
    if method == "pca":
        p = PCA(n_components=0.95, svd_solver="full").fit(Xtr)
        R = X - p.inverse_transform(p.transform(X))
        return (R ** 2).sum(axis=1)                       # squared prediction error
    f = IsolationForest(n_estimators=200, random_state=0).fit(Xtr)
    return -f.score_samples(X)                            # higher = more anomalous


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parsed", nargs="+", required=True)
    ap.add_argument("--out", default="results/window_baselines.csv")
    a = ap.parse_args()

    df = pd.concat([pd.read_parquet(p) for p in a.parsed], ignore_index=True)
    df["split"] = split_of(df.ts)
    df["win"] = df.ts.dt.floor("1min")
    df["wid"] = df.groupby(["ip", "win"]).ngroup()      # one integer id per (IP, minute)
    atk = df.attack.values.astype(bool)
    labels = df.attack_labels.astype(str)
    valid_n = (df.split.values == "valid") & ~atk
    test = df.split.values == "test"

    rows = []
    for variant, col in (("with_ua", "event"), ("no_ua", "event_noua")):
        vocab = sorted(df.loc[df.split == "train", col].unique())
        for unseen_col in (True, False):
            X, idx = window_matrix(df, col, vocab, unseen_col)
            wsplit = df.groupby("wid").split.first().reindex(idx).values
            pos = idx.get_indexer(df.wid.values)
            assert (pos >= 0).all(), "some events were not mapped to a window"
            for method in ("pca", "iforest"):
                s = scores(method, X[wsplit == "train"], X)[pos]
                assert np.isfinite(s).all(), "non-finite scores"
                for fpr in (0.01, 0.05):
                    thr = float(np.quantile(s[valid_n], 1 - fpr))
                    alarm = s > thr
                    r = {"method": method, "variant": variant,
                         "unseen_feature": unseen_col, "target_fpr": fpr,
                         "n_train_windows": int((wsplit == "train").sum()),
                         "valid_fpr": float(alarm[valid_n].mean()),
                         "test_fpr": float(alarm[test & ~atk].mean()),
                         "attack_recall": float(alarm[test & atk].mean())}
                    for st in STEPS:
                        m = test & labels.str.contains(st).values
                        r[st] = float(alarm[m].mean()) if m.any() else np.nan
                    rows.append(r)

    out = pd.DataFrame(rows)
    out.to_csv(a.out, index=False)
    show = out.copy()
    for c in ["valid_fpr", "test_fpr", "attack_recall"] + STEPS:
        show[c] = (100 * show[c]).round(1)
    print(show.drop(columns=["n_train_windows"]).to_string(index=False))
    print(f"\ntraining windows: {out.n_train_windows.iloc[0]}  | saved {a.out}")


if __name__ == "__main__":
    main()
