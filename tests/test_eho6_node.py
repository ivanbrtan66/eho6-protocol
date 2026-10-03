"""Testovi za eho6_node.py (stdlib + pytest). Pokretanje: python3 -m pytest tests -v

Poznati nedostaci su xfail(strict=True): kad se popravi kod, test PADA dok se
oznaka ne ukloni, pa popravak ne može proći nezapaženo.
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


@pytest.mark.xfail(strict=True, reason="README: F(32)=2178309, kod koristi 3524578 = F(33)")
def test_phi_xor_matches_readme():
    assert n.PHI_XOR == 2178309


@pytest.mark.xfail(strict=True, reason="negativan iznos ide u RIBOSOM, NaN u VM_JEZGRA; treba odbiti")
@pytest.mark.parametrize("bad", [-5, float("nan"), float("inf")])
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


@pytest.mark.xfail(strict=True, reason="'abc' kao iznos baca ValueError -> 500 umjesto 400")
def test_verify_bad_amount_is_client_error(server):
    assert _post(server + "/eho6/verify", {"order": {"amount": "abc"}}).code == 400


@pytest.mark.xfail(strict=True, reason="ACAO:* na /eho6/login koji vraća session_token: svaka web-stranica ga može pročitati")
def test_no_wildcard_cors_on_login(server):
    n.genesis_login = lambda: {"token": "x", "phi_t": "1"}
    n.genesis_bridge = lambda t: {"session_token": "S", "weise3_id": "W"}
    r = _post(server + "/eho6/login", {})
    assert r.headers.get("Access-Control-Allow-Origin") != "*"
