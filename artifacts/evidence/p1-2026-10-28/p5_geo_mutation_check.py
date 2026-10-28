import subprocess, pathlib
M = [
 ("inbound claimed enforced", "src/afw/policy/service.py", '            v["traffic_inbound"] = "n/a: no real-country inbound traffic reaches the lab"\n            verified = False', '            v["traffic_inbound"] = "n/a: no real-country inbound traffic reaches the lab"'),
 ("control target ignored", "src/afw/policy/service.py", "        if ctl is not True:", "        if False:"),
 ("partial table counts as present", "src/afw/policy/geo.py", "self.networks(cc) <= table", "self.networks(cc) & table"),
 ("AI may request countries", "src/afw/policy/validator.py", "        if intent.origin is PolicyOrigin.AI:", "        if False:"),
 ("firewall role not below viewer", "src/afw/api/auth.py", "    FIREWALL = 0", "    FIREWALL = 1"),
 ("non-global networks published", "src/afw/policy/geo.py", " for n in db.networks(cc) if n.is_global)", " for n in db.networks(cc))"),
 ("budget not enforced", "src/afw/policy/geo.py", "        if len(nets) > self.cfg.max_networks:", "        if False:"),
 ("stale database accepted", "src/afw/policy/validator.py", '        if status.get("stale"):', "        if False:"),
 ("read-back of removal skipped", "src/afw/enforcement/opnsense.py", "frozenset(pub.countries) | self._geo_watch", "frozenset(pub.countries)"),
]
tests = ["tests/unit/test_geo_enforcement.py", "tests/integration/test_api.py"]
caught = 0
for name, f, a, b in M:
    p = pathlib.Path(f); src = p.read_text(); assert src.count(a) == 1, name
    p.write_text(src.replace(a, b))
    try:
        r = subprocess.run(["uv","run","pytest","-o","addopts=","-q","-x",*tests], capture_output=True, text=True)
    finally:
        p.write_text(src)
    ok = r.returncode != 0; caught += ok
    print(f"{'CAUGHT ' if ok else 'SURVIVED'} {name}")
print(f"{caught}/{len(M)} mutants caught")
