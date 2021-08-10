import os
import pytest
import shutil
import logging
import datetime
import base64
import asyncio

from fastapi.testclient import TestClient


config = {
    "without-cs": ("test_config.yaml", "test-out"),
    "with-cs": ("test_config_with_cs.yaml", "test-out-with-cs"),
}


@pytest.fixture(scope="module", params=["without-cs", "with-cs"])
def config_file(request):
    return (
        os.path.join(os.path.dirname(__file__), config[request.param][0]),
        os.path.join(os.path.dirname(__file__), config[request.param][1]),
    )


def has_opt_cs(param):
    return param[0].endswith("test_config_with_cs.yaml")


auth_token = base64.b64encode(os.urandom(33)).decode("ascii")
os.environ["AUTH_TOKEN"] = auth_token
os.environ["NO_RENEW"] = "1"

import authsign.main

from authsign.utils import format_date
from authsign import signer, __version__

import authsign.crypto as crypto


app = authsign.main.app

logger = logging.getLogger("authsign")
logger.setLevel(logging.DEBUG)

# out_dir = os.path.join(os.path.dirname(__file__), "test-out")

cert_pem = None
cs_cert_pem = None
signed_hash = None
keep_data = False


def load_file(filename, out_dir):
    with open(os.path.join(out_dir, filename)) as fh:
        return fh.read()


def teardown_module():
    if keep_data:
        return

    paths = [
        os.path.join(os.path.dirname(__file__), "test-out"),
        os.path.join(os.path.dirname(__file__), "test-out-with-cs"),
    ]
    for out_dir in paths:
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)


def test_invalid_domain(port, keep, config_file):
    if keep:
        global keep_data
        keep_data = True

    if os.path.exists(config_file[1]):
        pytest.skip("reusing existing cert, skip invalid domain check")

    os.environ["DOMAIN_OVERRIDE"] = "example.com"
    os.environ["PORT_OVERRIDE"] = port
    os.environ["NO_RENEW"] = "1"
    os.environ["CONFIG"] = config_file[0]
    with pytest.raises(Exception):
        with TestClient(app) as client:
            pass


def test_inited(domain, port, config_file):
    os.environ["DOMAIN_OVERRIDE"] = domain
    os.environ["PORT_OVERRIDE"] = port
    os.environ["NO_RENEW"] = "1"
    os.environ["CONFIG"] = config_file[0]
    with TestClient(app) as client:
        global cert_pem
        cert_pem = load_file("cert.pem", config_file[1])

        res = set(os.listdir(config_file[1]))

        if has_opt_cs(config_file):
            assert res == {"cert.pem", "cs-cert.pem", "private-key.pem"}

            global cs_cert_pem
            cs_cert_pem = load_file("cs-cert.pem", config_file[1])
        else:
            assert res == {"cert.pem", "private-key.pem"}


def test_reload_same_cert(domain, config_file):
    with TestClient(app) as client:
        assert cert_pem == load_file("cert.pem", config_file[1])

        if has_opt_cs(config_file):
            assert cs_cert_pem == load_file("cs-cert.pem", config_file[1])


def test_sign_invalid_token(domain, config_file):
    req = {"hash": "some_data", "created": format_date(datetime.datetime.utcnow())}

    with TestClient(app) as client:
        resp = client.post("/sign", json=req)
        assert resp.status_code == 403

        resp = client.post(
            "/sign",
            headers={
                "Authorization": "bearer " + base64.b64encode(b"abc").decode("ascii")
            },
            json=req,
        )
        assert resp.status_code == 403


def test_sign_valid_token(domain, config_file):
    now = format_date(datetime.datetime.utcnow())
    req = {"hash": "some_data", "created": now}

    global signed_hash
    with TestClient(app) as client:
        resp = client.post(
            "/sign", headers={"Authorization": "bearer " + auth_token}, json=req
        )
        assert resp.status_code == 200
        signed_hash = resp.json()

    expected = {
        "hash",
        "created",
        "software",
        "domain",
        "domainCert",
        "signature",
        "timestampCert",
        "timeSignature",
        "version",
    }

    if has_opt_cs(config_file):
        expected.add("crossSignedCert")

    assert set(signed_hash.keys()) == expected

    assert signed_hash["hash"] == "some_data"
    assert signed_hash["created"] == now

    assert signed_hash["domain"] == domain
    assert signed_hash["software"] == "authsigner " + __version__


def test_sign_valid_token_bad_date(domain, config_file):
    req = {
        "hash": "some_data",
        "created": format_date(datetime.datetime.utcnow() - datetime.timedelta(days=1)),
    }

    global signed_hash
    with TestClient(app) as client:
        resp = client.post(
            "/sign", headers={"Authorization": "bearer " + auth_token}, json=req
        )
        assert resp.status_code == 400


def test_verify_invalid_missing(domain, config_file):
    with TestClient(app) as client:
        req = signed_hash.copy()
        req.pop("timeSignature", "")
        resp = client.post("/verify", json=req)
        assert resp.status_code == 422


def test_verify_invalid_hash(domain, config_file):
    with TestClient(app) as client:
        req = signed_hash.copy()
        req["hash"] = "other data"
        resp = client.post("/verify", json=req)
        assert resp.status_code == 400


def test_verify_wrong_cert(domain, config_file):
    with TestClient(app) as client:
        req = signed_hash.copy()
        req["timestampCert"] = req["domainCert"]
        resp = client.post("/verify", json=req)
        assert resp.status_code == 400


def test_verify_wrong_cross_signed_cert(domain, config_file):
    with TestClient(app) as client:
        req = signed_hash.copy()
        req["crossSignedCert"] = req["timestampCert"]
        resp = client.post("/verify", json=req)
        assert resp.status_code == 400


def test_verify_invalid_bad_date(domain, config_file):
    with TestClient(app) as client:
        # date to early
        req = signed_hash.copy()
        req["created"] = "abc"
        resp = client.post("/verify", json=req)
        assert resp.status_code == 400


def test_verify_invalid_date_out_of_range(domain, config_file):
    with TestClient(app) as client:
        # date to early
        req = signed_hash.copy()
        req["created"] = format_date(
            datetime.datetime.utcnow() - datetime.timedelta(days=1)
        )
        resp = client.post("/verify", json=req)
        assert resp.status_code == 400

        # date to late
        req = signed_hash.copy()
        req["created"] = format_date(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        )
        resp = client.post("/verify", json=req)
        assert resp.status_code == 400


def test_verify_valid(domain, config_file):
    with TestClient(app) as client:
        resp = client.post("/verify", json=signed_hash)
        assert resp.status_code == 200
        res = resp.json()
        assert res["observer"] == domain
        assert res["timestamp"]


@pytest.mark.asyncio
async def test_renew_cert(domain):
    orig_cert_pem = cert_pem

    authsign.main.signer.next_update = 5
    asyncio.ensure_future(authsign.main.signer.renew_loop())

    await asyncio.sleep(7)

    while signer.renewing:
        await asyncio.sleep(0.5)

    new_cert_pem = load_file("cert.pem", os.path.join(os.path.dirname(__file__), "test-out"))

    assert new_cert_pem != orig_cert_pem
