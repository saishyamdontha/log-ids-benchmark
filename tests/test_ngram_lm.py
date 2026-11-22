import random, sys
sys.path.insert(0, "src")
from ngram_lm import NgramLM, choose_order

def make_stream(n, rng):
    paths = [["login","post","dash","view","view","logout"],
             ["login","post","dash","list","view","logout"],
             ["home","about","home","contact"]]
    out = []
    for _ in range(n):
        p = list(rng.choice(paths))
        if rng.random() < 0.1:
            p.insert(rng.randint(1, len(p) - 1), "static")
        out += p
    return out

def test_order_chosen_on_normal_data_and_attack_scores_higher():
    rng = random.Random(1)
    train = [make_stream(300, rng) for _ in range(4)]
    valid = [make_stream(100, rng) for _ in range(2)]
    best, _ = choose_order(train, valid, verbose=False)
    assert 3 <= best <= 5
    m = NgramLM(max_n=best).fit(train)
    normal = make_stream(20, rng)
    attack = make_stream(5, rng) + ["login","fail","fail","fail","post","dash","upload","exec"] + make_stream(5, rng)
    avg = lambda x: sum(x) / len(x)
    assert avg(m.surprisals(attack)) > 3 * avg(m.surprisals(normal))

def test_unseen_template_has_nonzero_probability():
    m = NgramLM(max_n=3).fit([["a", "b", "a", "b"]])
    assert 0 < m.prob("zzz", ["a", "b"]) < 0.5
