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


# --- Nalaz 9: admit.json se provjerava protiv ugrađenih sidara --------------------
# Stvarni testni admit s EU (eho6_anchor/admits/test_node_001.admit.json, simulacija, 26.6.2026.)
ADMIT_TEST_NODE_001 = {
    "candidate_pk": "ff3c168bec7fe4f78686832ed212389543d498a08e6963fd50ac83973c65b424",
    "agent_id": "test_node_001",
    "word": "test",
    "nastao": "2026-06-26T02:43:16.668568+00:00",
    "threshold": 2,
    "body_sha": "587afb858fc001e3fa7a37ac5cc80bb8a6117875b3ad048fee63952a309f8985",
    "signatures": [
        {"anchor_node": "ubuntu",
         "anchor_pk": "4d628b9cfeac2912faee20c9421cea91c227075a39105bb12c713483a4f46b13",
         "sig": "IMFcXXRUO0/PzkgYJXT1c0yXxQ4aClsD52FarWx31vjxbY7GI/Nb7mlFsh8e3kR/IxE/5hAZlSN1F+98m8VQAg=="},
        {"anchor_node": "genesis-de",
         "anchor_pk": "d210246f0f45cb256315c44d97f4c1a7ae95342e695fbc4a5f5b3fbef421dc8f",
         "sig": "GCgKjMJdgz8eRCDyjNX6z/AvOOiW7trEbCUEfp4/690P/kyv+bEoJr6700Eef9JEcE+iGar2HgzKE6Msbs+uCg=="},
    ],
    "status": "ADMITTED",
    "tx_hash": "sim_tx_5b89d7a0e08712726104769e85d1dec7",
    "admit_mode": "simulation",
}


def _admit(**changes):
    a = json.loads(json.dumps(ADMIT_TEST_NODE_001))
    a.update(changes)
    return a


def test_rfc8032_verify_vector():
    assert n.ed25519_verify(bytes.fromhex(PK1), bytes.fromhex(SIG1), b"")
    bad = bytearray(bytes.fromhex(SIG1)); bad[0] ^= 1
    assert not n.ed25519_verify(bytes.fromhex(PK1), bytes(bad), b"")
    assert not n.ed25519_verify(bytes.fromhex(PK1), bytes.fromhex(SIG1), b"x")


def test_verify_rejects_s_not_reduced():
    sig = bytearray(bytes.fromhex(SIG1))
    s = int.from_bytes(sig[32:], "little") + n.Q  # isti potpis, S + L: mora biti odbijen (malleability)
    assert s < 2**256
    sig[32:] = s.to_bytes(32, "little")
    assert not n.ed25519_verify(bytes.fromhex(PK1), bytes(sig), b"")


def test_ed25519_verify_crosscheck_with_cryptography():
    ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    import os
    for i in range(30):
        sk = ed.Ed25519PrivateKey.from_private_bytes(os.urandom(32))
        pk = sk.public_key().public_bytes_raw()
        msg = os.urandom(i * 5)
        sig = sk.sign(msg)
        assert n.ed25519_verify(pk, sig, msg)
        flipped = bytearray(sig); flipped[i % 64] ^= 0x40
        assert not n.ed25519_verify(pk, bytes(flipped), msg)


def test_real_admit_holds():
    verdict, why = n.verify_admit(ADMIT_TEST_NODE_001, ADMIT_TEST_NODE_001["candidate_pk"])
    assert verdict == n.DRZI, why
    assert "genesis-eu" in why and "genesis-de" in why


@pytest.mark.parametrize("admit,why", [
    (_admit(word="other"), "body_sha"),                       # tijelo promijenjeno
    (_admit(status="EU_SIGNED"), "status"),
    (_admit(signatures=ADMIT_TEST_NODE_001["signatures"][:1]), "1 valid"),
    (_admit(signatures=[ADMIT_TEST_NODE_001["signatures"][0]] * 2), "1 valid"),  # isti EU potpis dvaput
    (_admit(signatures=[dict(ADMIT_TEST_NODE_001["signatures"][0]),
                        dict(ADMIT_TEST_NODE_001["signatures"][1], anchor_pk="ab" * 32)]), "1 valid"),
    (_admit(signatures=[ADMIT_TEST_NODE_001["signatures"][0],
                        dict(ADMIT_TEST_NODE_001["signatures"][1], sig="!!notb64!!")]), "1 valid"),
])
def test_tampered_admit_fails(admit, why):
    verdict, reason = n.verify_admit(admit)
    assert verdict == n.PAD and why in reason


def test_admit_for_other_node_fails():
    verdict, reason = n.verify_admit(ADMIT_TEST_NODE_001, "00" * 32)
    assert verdict == n.PAD and "candidate_pk" in reason


@pytest.mark.parametrize("admit", [None, [], "x", {"status": "ADMITTED"},
                                   # jednopotpisni zapis kao racva010v1v2td219f51e.admit.json na EU
                                   {"agent_id": "a", "candidate_pk": "00" * 32, "sig": "x", "anchor_pk": "4d"},
                                   _admit(signatures="nope")])
def test_malformed_admit_is_unknown(admit):
    assert n.verify_admit(admit)[0] == n.NEPOZNATO


def test_node_state_trusts_signatures_not_file_status(tmp_path, monkeypatch):
    monkeypatch.setattr(n, "EHO6_DIR", tmp_path)
    (tmp_path / "config.json").write_text(json.dumps({"agent_id": "t"}))
    (tmp_path / "node.key").write_bytes(b"\x01" * 32)
    forged = _admit(word="forged")  # status kaže ADMITTED, ali potpisi ne odgovaraju
    (tmp_path / "admit.json").write_text(json.dumps(forged))
    st = n.NodeState(); st.load()
    assert st.admit_status == "ADMIT_PAD" and st.admit_verdict == n.PAD
    (tmp_path / "admit.json").write_text("{not json")
    st = n.NodeState(); st.load()
    assert st.admit_status == "ADMIT_NEPOZNATO"


def test_anchor_set_has_no_retired_mar():
    assert "9f3d60f9c91827952599b2bbf67b474d9e0807950a36fba80fcb6eaadc848c30" not in n.ANCHOR_PKS
    assert set(n.ANCHOR_PKS.values()) == {"genesis-eu", "genesis-de", "genesis-es"}
