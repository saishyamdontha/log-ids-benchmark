"""Variable-order n-gram language model over log templates.

Learns from NORMAL sequences only. For each next template it uses the longest
context seen in training and backs off to shorter contexts when needed
(Witten-Bell interpolation), so every template, even an unseen one, gets a
probability above zero.

choose_order() picks the maximum context length on held-out NORMAL data:
the order whose average surprisal (bits per event) is lowest. No attack
labels are used anywhere in this file.
"""
import math
from collections import defaultdict, Counter

UNK = "<UNK>"


class NgramLM:
    def __init__(self, max_n=6):
        self.max_n = max_n                       # longest context = max_n - 1 templates
        self.counts = defaultdict(Counter)       # context tuple -> Counter(next template)
        self.vocab = set()

    def fit(self, sequences):
        for seq in sequences:
            for i, t in enumerate(seq):
                self.vocab.add(t)
                for k in range(0, self.max_n):   # context lengths 0 .. max_n-1
                    if i - k < 0:
                        break
                    self.counts[tuple(seq[i - k:i])][t] += 1
        return self

    def prob(self, t, context):
        """P(t | context), interpolated from the longest context down to uniform."""
        context = tuple(context[-(self.max_n - 1):]) if self.max_n > 1 else ()
        p = 1.0 / (len(self.vocab) + 1)          # base: uniform over vocab + one unknown slot
        for k in range(0, len(context) + 1):     # build up from short to long context
            h = context[len(context) - k:]
            c = self.counts.get(h)
            if not c:
                break                            # longer contexts were never seen either
            total = sum(c.values())
            types = len(c)
            p = (c.get(t, 0) + types * p) / (total + types)
        return p

    def surprisals(self, seq):
        """Bits of surprise for each event in seq, given the events before it."""
        out = []
        for i, t in enumerate(seq):
            out.append(-math.log2(self.prob(t, seq[max(0, i - self.max_n + 1):i])))
        return out


def avg_bits(model, sequences):
    bits = [b for s in sequences for b in model.surprisals(s)]
    return sum(bits) / len(bits)


def choose_order(train, valid, orders=range(1, 9), verbose=True):
    """Pick max_n on NORMAL validation data only. Returns (best_n, table)."""
    table = {}
    for n in orders:
        table[n] = avg_bits(NgramLM(max_n=n).fit(train), valid)
        if verbose:
            print(f"  max_n={n}: {table[n]:.3f} bits/event on normal validation")
    best = min(table, key=table.get)
    return best, table
