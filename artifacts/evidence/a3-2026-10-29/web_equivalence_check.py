import importlib.util, random, sys, json
def trace(path, seed, src, n=30, v2=True):
    spec = importlib.util.spec_from_file_location("g"+str(abs(hash(path))), path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    m.PERSONA_SET = "v2" if v2 else "v1"; m.REVIEWS = False
    out = []
    def req(source, method, path, cookie=None, body=None):
        out.append((method, path, json.dumps(body, sort_keys=True))); return 200, ("s" if path == "/login" and body and body["password"] != "wrong" else None), b'{"id": 1}'
    m._request = lambda *a, **k: req(*a, **k)[:2]
    m._request_full = req
    m.time.sleep = lambda x: out.append(("sleep", round(x, 9)))
    rng = random.Random(seed)
    p = m.persona_v2(rng) if v2 else m.persona(rng)
    for _ in range(n):
        (m.journey_v2 if v2 else m.journey)(rng, src, p)
    return p, out
old, new = sys.argv[1], sys.argv[2]
for seed in [913000 + i for i in range(16)] + [811000, 815003, 1, 42]:
    a, b = trace(old, seed, "10.77.20.140"), trace(new, seed, "10.77.20.140")
    assert a == b, seed
print("identical web journeys for 20 seeds x 30 sessions")
