import os
import pytest
import shutil
import logging
import datetime
import base64

from fastapi.testclient import TestClient

os.environ["CONFIG"] = os.path.join(os.path.dirname(__file__), "test_config.yaml")
from reqsigner.main import app

import reqsigner.crypto as crypto

logger = logging.getLogger("signer")
logger.setLevel(logging.DEBUG)

out_dir = os.path.join(os.path.dirname(__file__), "test-out")

cert_pem = None
auth_token = None
signed_req = None


def load_file(filename):
    with open(os.path.join(out_dir, filename)) as fh:
        return fh.read()


def teardown_module():
    shutil.rmtree(out_dir)


def test_inited(domain):
    os.environ["DOMAIN_OVERRIDE"] = domain
    with TestClient(app) as client:
        res = sorted(os.listdir(out_dir))
        assert res == [
            "auth-token.txt",
            "cert.pem",
            "long-private-key.pem",
            "long-public-key.pem",
            "private-key.pem",
            "public-key.pem",
        ]

        global cert_pem
        cert_pem = load_file("cert.pem")

        global auth_token
        auth_token = load_file("auth-token.txt")


def test_reload_same_cert(domain):
    with TestClient(app) as client:
        assert cert_pem == load_file("cert.pem")
        assert auth_token == load_file("auth-token.txt")


def test_sign_invalid_token(domain):
    with TestClient(app) as client:
        resp = client.post("/sign/some-data")
        assert resp.status_code == 403

        resp = client.post(
            "/sign/some-data",
            headers={
                "Authorization": "bearer " + base64.b64encode(b"abc").decode("ascii")
            },
        )
        assert resp.status_code == 403


def test_sign_valid_token(domain):
    global signed_req
    with TestClient(app) as client:
        resp = client.post(
            "/sign/some-data", headers={"Authorization": "bearer " + auth_token}
        )
        assert resp.status_code == 200
        signed_req = resp.json()


def test_verify_invalid_missing(domain):
    with TestClient(app) as client:
        req = signed_req.copy()
        req.pop("timeSignature", "")
        resp = client.post("/verify", json=req)
        assert resp.status_code == 422


def test_verify_invalid_hash(domain):
    with TestClient(app) as client:
        req = signed_req.copy()
        req["hash"] = "other data"
        resp = client.post("/verify", json=req)
        assert resp.status_code == 400


def test_verify_invalid_wrong_key(domain):
    private_key = crypto.create_ecdsa_private_key()
    public_key = private_key.public_key()
    with TestClient(app) as client:
        req = signed_req.copy()
        req["privateKey"] = crypto.save_private_key(private_key, b"passphrase").decode(
            "ascii"
        )
        req["publicKey"] = crypto.get_public_key_pem(public_key)
        resp = client.post("/verify", json=req)
        assert resp.status_code == 400


def test_verify_invalid_bad_date(domain):
    with TestClient(app) as client:
        # date to early
        req = signed_req.copy()
        req["date"] = (
            datetime.datetime.utcnow() - datetime.timedelta(days=1)
        ).isoformat()
        resp = client.post("/verify", json=req)
        assert resp.status_code == 400

        # date to late
        req = signed_req.copy()
        req["date"] = (
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).isoformat()
        resp = client.post("/verify", json=req)
        assert resp.status_code == 400


def test_verify_valid(domain):
    with TestClient(app) as client:
        resp = client.post("/verify", json=signed_req)
        assert resp.status_code == 200
        assert resp.json() == {"domain": domain}
