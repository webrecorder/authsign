import asyncio
import os
import datetime

from fastapi import FastAPI, HTTPException, Header

from authsign.signer import Signer
from authsign.verifier import Verifier
from authsign.model import SignedHash, SignReq

from authsign.utils import load_yaml, CERT_DURATION, STAMP_DURATION

from authsign.log import log_message, log_failure


app = FastAPI()

signer = None
verifier = None


def load_certs(server):
    configfile = os.environ.get("CONFIG", "config.yaml")

    global signer
    log_message("Loading config from: " + configfile)

    config = load_yaml(configfile)

    if os.environ.get("DOMAIN_OVERRIDE"):
        config["signing"]["domain"] = os.environ.get("DOMAIN_OVERRIDE")

    if os.environ.get("EMAIL_OVERRIDE"):
        config["signing"]["email"] = os.environ.get("EMAIL_OVERRIDE")

    if os.environ.get("DATA_OVERRIDE"):
        config["signing"]["data"] = os.environ.get("DATA_OVERRIDE")

    if os.environ.get("PORT_OVERRIDE"):
        config["signing"]["port"] = int(os.environ.get("PORT_OVERRIDE"))

    if os.environ.get("AUTH_TOKEN"):
        config["signing"]["auth_token"] = os.environ.get("AUTH_TOKEN")

    if "cert_duration" in config:
        cert_duration = datetime.timedelta(**config.get("cert_duration"))
    else:
        cert_duration = CERT_DURATION

    if "stamp_duration" in config:
        stamp_duration = datetime.timedelta(**config.get("stamp_duration"))
    else:
        stamp_duration = STAMP_DURATION

    log_message(f"Certificate rotation time: {cert_duration}")
    log_message(f"Timestamp validity time: {stamp_duration}")

    log_message("")
    log_message("Signer init...")
    signer = Signer(
        cert_duration=cert_duration, stamp_duration=stamp_duration, **config["signing"]
    )

    if not os.environ.get("NO_RENEW"):
        asyncio.ensure_future(signer.renew_loop())

    global verifier
    log_message("")
    log_message("Verifier Init...")
    verifier = Verifier(config.get("trusted_roots"), cert_duration, stamp_duration)
    log_message("")


@app.post("/sign", response_model=SignedHash, response_model_exclude_none=True)
async def sign_data(sign_req: SignReq, authorization: str = Header(None)):
    log_message("Signing Request...")
    if not signer.validate_token(authorization):
        log_failure("Invalid Auth Token")
        raise HTTPException(status_code=403, detail="Invalid auth token")

    try:
        return signer(sign_req)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/verify")
async def verify_data(signed_hash: SignedHash):
    log_message("Verifying Signed Request...")
    # result = await loop.run_in_executor(None, verifier, signed_hash)
    # if result:
    #    return result
    try:
        result = verifier(signed_hash)
        if result:
            return result
    except Exception as e:
        pass

    raise HTTPException(status_code=400, detail="Not verified")
