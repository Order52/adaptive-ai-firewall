"""A3: the WAF helper renders login controls on the login routes only."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def helper(tmp_path_factory):
    tok = tmp_path_factory.mktemp("h") / "token"
    tok.write_text("t")
    os.environ["AFW_HELPER_TOKEN_FILE"] = str(tok)
    spec = importlib.util.spec_from_file_location(
        "afw_waf_helper", ROOT / "waf" / "helper" / "afw_waf_helper.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["afw_waf_helper"] = mod
    spec.loader.exec_module(mod)
    return mod


EMPTY = {"denied_sources": [], "rate_limited": {}, "contracts": []}


def test_old_documents_still_validate(helper):
    assert helper.validate(EMPTY) == EMPTY  # no login_controls key added when empty


def test_login_controls_validate(helper):
    doc = EMPTY | {"login_controls": {"10.77.20.150": "throttle", "10.77.10.10": "deny"}}
    out = helper.validate(doc)
    assert out["login_controls"] == {"10.77.10.10": "deny", "10.77.20.150": "throttle"}
    with pytest.raises(helper.Invalid):
        helper.validate(EMPTY | {"login_controls": {"10.77.20.150": "lockout"}})
    with pytest.raises(helper.Invalid):  # management is never a client address
        helper.validate(EMPTY | {"login_controls": {"10.77.50.10": "deny"}})
    with pytest.raises(helper.Invalid):
        helper.validate(EMPTY | {"extra": 1})


def test_render_scopes_the_controls_to_the_login_route(helper):
    state = helper.validate(
        EMPTY | {"login_controls": {"10.77.20.150": "throttle", "10.77.10.10": "deny"}}
    )
    conf = helper.render(state, 7)
    http, server = conf["http.conf"], conf["server.conf"]
    assert "10.77.20.150/32 throttle;" in http and "10.77.10.10/32 deny;" in http
    assert "zone=afw_login:1m rate=3r/m;" in http
    loc = server[server.index("location = /login {") :]
    loc = loc[: loc.index("}\n", loc.index("include")) + 1]
    assert 'if ($afw_login_class = "deny") { return 403; }' in loc
    assert "limit_req zone=afw_login burst=4 nodelay;" in loc
    # nginx does not inherit limit_req into a location that sets its own
    assert "limit_req zone=afw_strict" in loc and "limit_req zone=afw_moderate" in loc
    assert "include /etc/nginx/afw/proxy_backend.conf;" in loc
    # the login zone is used nowhere else
    assert server.count("zone=afw_login") == 1


def test_login_location_merges_with_a_login_contract(helper):
    contract = {
        "type": "contract",
        "route": "/login",
        "allowed_methods": ["POST"],
        "allowed_content_types": ["application/json"],
        "max_body_bytes": 1024,
        "revision": 1,
    }
    state = helper.validate(EMPTY | {"contracts": [contract]})
    server = helper.render(state, 8)["server.conf"]
    assert server.count("location = /login {") == 1
    assert "limit_except POST" in server and "zone=afw_login" in server
