"""LSTM next-event language model over log events (DeepLog-style), CPU-friendly.

Trained on NORMAL sequences only (one sequence per source IP). For every event it
predicts a probability over the training vocabulary plus <UNK>; an event never seen
in training gets the probability of <UNK>. Early stopping uses NORMAL validation loss.
"""
import math, random
import numpy as np
import torch
import torch.nn as nn

UNK, PAD = "<UNK>", "<PAD>"


class _Net(nn.Module):
    def __init__(self, vocab, emb=32, hidden=64):
        super().__init__()
        self.emb = nn.Embedding(vocab, emb, padding_idx=0)
        self.lstm = nn.LSTM(emb, hidden, batch_first=True)
        self.out = nn.Linear(hidden, vocab)

    def forward(self, x):
        h, _ = self.lstm(self.emb(x))
        return self.out(h[:, -1])


class LSTMLM:
    def __init__(self, history=10, emb=32, hidden=64, epochs=60, patience=6, lr=3e-3, seed=0):
        self.h, self.emb, self.hidden = history, emb, hidden
        self.epochs, self.patience, self.lr, self.seed = epochs, patience, lr, seed

    def _ids(self, seq):
        return [self.idx.get(t, self.idx[UNK]) for t in seq]

    def _windows(self, seqs):
        X, Y = [], []
        for seq in seqs:
            ids = self._ids(seq)
            for i in range(len(ids)):
                ctx = ids[max(0, i - self.h):i]
                X.append([0] * (self.h - len(ctx)) + ctx)
                Y.append(ids[i])
        return torch.tensor(X, dtype=torch.long), torch.tensor(Y, dtype=torch.long)

    def fit(self, train, valid, verbose=True):
        torch.manual_seed(self.seed); random.seed(self.seed); np.random.seed(self.seed)
        vocab = sorted({t for s in train for t in s})
        self.itos = [PAD, UNK] + vocab
        self.idx = {t: i for i, t in enumerate(self.itos)}
        self.net = _Net(len(self.itos), self.emb, self.hidden)
        Xtr, Ytr = self._windows(train)
        Xva, Yva = self._windows(valid)
        opt = torch.optim.Adam(self.net.parameters(), lr=self.lr)
        lossf = nn.CrossEntropyLoss()
        best, best_state, bad = float("inf"), None, 0
        for ep in range(self.epochs):
            self.net.train()
            perm = torch.randperm(len(Xtr))
            for b in range(0, len(Xtr), 256):
                j = perm[b:b + 256]
                opt.zero_grad()
                lossf(self.net(Xtr[j]), Ytr[j]).backward()
                opt.step()
            self.net.eval()
            with torch.no_grad():
                vl = lossf(self.net(Xva), Yva).item()
            if verbose:
                print(f"  epoch {ep+1:2d}  valid loss {vl/math.log(2):.3f} bits")
            if vl < best - 1e-4:
                best, bad = vl, 0
                best_state = {k: v.clone() for k, v in self.net.state_dict().items()}
            else:
                bad += 1
                if bad >= self.patience:
                    break
        self.net.load_state_dict(best_state)
        self.net.eval()
        return self

    def probs(self, seq):
        """P(event_i | previous events) for each event in seq."""
        X, Y = self._windows([seq])
        out = []
        with torch.no_grad():
            for b in range(0, len(X), 2048):
                p = torch.softmax(self.net(X[b:b + 2048]), dim=1)
                out.append(p[torch.arange(len(p)), Y[b:b + 2048]].numpy())
        return np.concatenate(out) if out else np.array([])
