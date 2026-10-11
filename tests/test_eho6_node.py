"""Testovi za eho6_node.py (stdlib + pytest). Pokretanje: python3 -m pytest tests -v

Nalazi §3 iz docs/IZVJESTAJ_verifikacija_2026-10-03.md (1, 2, 3, 4, 6, 8) su
popravljeni; njihovi nekadašnji xfail testovi sada su obični testovi.
"""
import base64
import importlib.util
import json
import struct
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

SPEC = importlib.util.spec_from_file_location("eho6_node", Path(__file__).parent.parent / "eho6_node.py")
n = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(n)

# RFC 8032 §7.1, TEST 1 i TEST 2
SK1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PK1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
SIG1 = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
SK2 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PK2 = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"


def test_rfc8032_test1_pubkey_and_signature():
    assert n.ed25519_pubkey(SK1).hex() == PK1
    assert n.ed25519_sign(SK1, b"").hex() == SIG1


def test_rfc8032_test2_pubkey():
    assert n.ed25519_pubkey(SK2).hex() == PK2


def test_ed25519_crosscheck_with_cryptography():
    ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    import os
    for i in range(30):
        sk, msg = os.urandom(32), os.urandom(i * 7)
        assert ed.Ed25519PrivateKey.from_private_bytes(sk).sign(msg) == n.ed25519_sign(sk, msg)


def test_fraktal_token_layout():
    n.STATE.agent_id = "t"
    tok, meta = n.build_fraktal_token({"amount": 50, "intent": 7, "flags": 3})
    raw = base64.b64decode(tok)
    assert len(raw) == 32
    organ, intent, flags, phi_t, anchor, payload = struct.unpack(">BBHI8s16s", raw)
    assert (organ, intent, flags) == (n.RIBOSOM, 7, 3)
    assert anchor.hex() == meta["anchor_hex"]
    assert payload == b'{"amount":50,"flags":3,"intent":7}'[:16]


def test_anchor_is_order_key_order_independent():
    a, _ = n.build_fraktal_token({"amount": 1, "side": "buy"})
    b, _ = n.build_fraktal_token({"side": "buy", "amount": 1})
    assert base64.b64decode(a)[8:16] == base64.b64decode(b)[8:16]


@pytest.mark.parametrize("amount,organ", [(0, 1), (99.99, 1), (100, 2), (9999, 2), (10000, 3)])
def test_classify_boundaries(amount, organ):
    assert n.classify_organ({"amount": amount}) == organ


def test_phi_t_fits_32_bits():
    assert 0 <= n.compute_phi_t() <= 0xFFFFFFFF


def test_phi_xor_matches_readme():
    a, b = 0, 1
    for _ in range(33):
        a, b = b, a + b
    assert n.PHI_XOR == a == 3524578  # F(33)
    assert "XOR F(33)" in (Path(__file__).parent.parent / "README.md").read_text()


@pytest.mark.parametrize("bad", [-5, float("nan"), float("inf"), "abc", "50", True, None])
def test_classify_rejects_invalid_amounts(bad):
    with pytest.raises(ValueError):
        n.classify_organ({"amount": bad})


@pytest.fixture()
def server():
    n.STATE.agent_id = "test"
    srv = HTTPServer(("127.0.0.1", 0), n.EHO6Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _post(url, obj):
    req = Request(url, data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        return urlopen(req, timeout=5)
    except Exception as e:  # HTTPError nosi odgovor
        return e


def test_health_ok(server):
    r = urlopen(server + "/health", timeout=5)
    assert r.status == 200 and json.loads(r.read())["agent_id"] == "test"


def test_verify_requires_order(server):
    assert _post(server + "/eho6/verify", {}).code == 400


def test_verify_returns_32_byte_token(server):
    r = _post(server + "/eho6/verify", {"order": {"amount": 5}})
    assert len(base64.b64decode(json.loads(r.read())["fraktal_token"])) == 32


def test_unknown_path_404(server):
    assert _post(server + "/nema", {}).code == 404


@pytest.mark.parametrize("order", [{"amount": "abc"}, {"amount": -1}, {"intent": 256}, {"flags": -1}, {"flags": "x"}])
def test_verify_bad_order_is_client_error(server, order):
    assert _post(server + "/eho6/verify", {"order": order}).code == 400


@pytest.mark.parametrize("field,maximum", [("intent", 0xFF), ("flags", 0xFFFF)])
def test_uint_fields_are_not_truncated(field, maximum):
    n.build_fraktal_token({field: maximum})
    with pytest.raises(ValueError):
        n.build_fraktal_token({field: maximum + 1})


@pytest.fixture()
def fake_login(monkeypatch):
    monkeypatch.setattr(n, "genesis_login", lambda: {"token": "x", "phi_t": "1"})
    monkeypatch.setattr(n, "genesis_bridge", lambda t: {"session_token": "S", "weise3_id": "W"})


def test_no_wildcard_cors_on_login(server, fake_login):
    r = _post(server + "/eho6/login", {})
    assert r.code == 200 and json.loads(r.read())["session_token"] == "S"
    assert r.headers.get("Access-Control-Allow-Origin") is None


def _post_h(url, headers):
    req = Request(url, data=b"{}", headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        return urlopen(req, timeout=5)
    except Exception as e:
        return e


def test_login_rejects_foreign_origin(server, fake_login):
    assert _post_h(server + "/eho6/login", {"Origin": "https://evil.example"}).code == 403


def test_login_rejects_rebinding_host(server, fake_login):
    assert _post_h(server + "/eho6/login", {"Host": "evil.example:8091"}).code == 403


def test_login_allows_local_origin_and_echoes_it(server, fake_login):
    origin = "http://localhost:3000"
    r = _post_h(server + "/eho6/login", {"Origin": origin})
    assert r.code == 200 and r.headers.get("Access-Control-Allow-Origin") == origin


@pytest.mark.parametrize("host,ok", [
    ("localhost:8091", True), ("127.0.0.1", True), ("[::1]:8091", True), ("LOCALHOST", True),
    ("localhost.evil.example", False), ("127.0.0.1.nip.io:8091", False), ("192.168.1.5:8091", False), ("", False),
])
def test_is_local_host(host, ok):
    assert n._is_local_host(host) is ok


def test_default_bind_is_loopback():
    assert n.NodeState().bind == "127.0.0.1"


# --- TLS: nikad CERT_NONE, nikad tihi HTTP -------------------------------------

def test_http_request_never_disables_cert_verification(monkeypatch):
    import ssl
    seen = []

    def fake_urlopen(req, timeout=None, context=None):
        seen.append(context)
        raise n.HTTPError(req.full_url, 500, "boom", {}, None) if len(seen) == 1 else AssertionError("retried")

    monkeypatch.setattr(n, "urlopen", fake_urlopen)
    with pytest.raises(n.HTTPError):
        n._http_request("https://example.invalid/x")
    assert len(seen) == 1
    assert seen[0].verify_mode == ssl.CERT_REQUIRED and seen[0].check_hostname


def _record_calls(monkeypatch, exc):
    urls = []

    def fake(url, **kw):
        urls.append(url)
        raise exc

    monkeypatch.setattr(n, "_http_request", fake)
    return urls


def test_api_call_no_http_fallback_by_default(monkeypatch):
    monkeypatch.setattr(n.STATE, "eu_https", "https://a")
    monkeypatch.setattr(n.STATE, "eu_http", "http://b")
    monkeypatch.setattr(n.STATE, "allow_insecure_http", False)
    urls = _record_calls(monkeypatch, OSError("tls"))
    with pytest.raises(OSError):
        n._api_call("/p")
    assert urls == ["https://a/p"]


def test_api_call_http_error_never_falls_back(monkeypatch):
    monkeypatch.setattr(n.STATE, "eu_https", "https://a")
    monkeypatch.setattr(n.STATE, "allow_insecure_http", True)
    urls = _record_calls(monkeypatch, n.HTTPError("https://a/p", 503, "x", {}, None))
    with pytest.raises(n.HTTPError):
        n._api_call("/p")
    assert urls == ["https://a/p"]


def test_api_call_http_fallback_only_when_opted_in(monkeypatch):
    monkeypatch.setattr(n.STATE, "eu_https", "https://a")
    monkeypatch.setattr(n.STATE, "eu_http", "http://b")
    monkeypatch.setattr(n.STATE, "allow_insecure_http", True)
    urls = _record_calls(monkeypatch, OSError("tls"))
    with pytest.raises(OSError):
        n._api_call("/p")
    assert urls == ["https://a/p", "http://b/p"]


def test_slow_login_does_not_block_health(monkeypatch):
    """ThreadingHTTPServer: /health odgovara dok /eho6/login visi."""
    from http.server import ThreadingHTTPServer
    release = threading.Event()
    monkeypatch.setattr(n, "genesis_login", lambda: (release.wait(10), {"token": ""})[1])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), n.EHO6Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        threading.Thread(target=_post, args=(base + "/eho6/login", {}), daemon=True).start()
        time.sleep(0.2)
        t0 = time.time()
        assert urlopen(base + "/health", timeout=3).status == 200
        assert time.time() - t0 < 1.0
    finally:
        release.set()
        srv.shutdown()


def test_run_server_uses_threading_server():
    src = (Path(__file__).parent.parent / "eho6_node.py").read_text()
    assert "ThreadingHTTPServer((STATE.bind, port)" in src and '"0.0.0.0"' not in src


def test_install_sh_key_permissions_and_no_insecure_transport():
    sh = (Path(__file__).parent.parent / "install.sh").read_text()
    assert 'chmod 700 "$EHO6_DIR"' in sh
    assert "umask 077" in sh
    assert "--insecure" not in sh and 'EU_BASE="$EU_HTTP"' not in sh
