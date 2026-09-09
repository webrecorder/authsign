"""main entrypoint for authsign web server"""

import asyncio
import os
import datetime
import traceback

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from fastapi import FastAPI, HTTPException, Header

from authsign.signer import Signer
from authsign.verifier import Verifier
from authsign.model import SignedHash, SignReq, VerifiedResponse

from authsign.utils import load_yaml, CERT_DURATION, STAMP_DURATION

from authsign.log import log_message, log_failure

signer: Signer | None = None
verifier: Verifier | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
    """load certs before starting FastAPI app"""
    await load_certs()
    yield


app = FastAPI(lifespan=lifespan)


async def load_certs() -> None:
    """load existing certs or request new ones if expired don't exist"""
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
        config["signing"]["port"] = int(os.environ.get("PORT_OVERRIDE", ""))

    if os.environ.get("AUTH_TOKEN"):
        config["signing"]["auth_token"] = os.environ.get("AUTH_TOKEN")

    if "cert_duration" in config:
        cert_duration = datetime.timedelta(**config.get("cert_duration", {}))
    else:
        cert_duration = CERT_DURATION

    if "stamp_duration" in config:
        stamp_duration = datetime.timedelta(**config.get("stamp_duration", {}))
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
async def sign_data(sign_req: SignReq, authorization: str = Header(None)) -> SignedHash:
    """sign data api"""
    if not signer:
        raise ValueError("No signer defined!")

    log_message("Signing Request...")
    if not signer.validate_token(authorization):
        log_failure("Invalid Auth Token")
        raise HTTPException(status_code=403, detail="Invalid auth token")

    try:
        return signer(sign_req)
    except Exception as e:
        detail = str(e)
        if not detail:
            detail = traceback.format_exc()
        raise HTTPException(status_code=400, detail=detail) from e


@app.post("/verify", response_model=VerifiedResponse)
async def verify_data(signed_hash: SignedHash) -> VerifiedResponse:
    """verify data api"""
    if not verifier:
        raise ValueError("No verifier defined!")

    log_message("Verifying Signed Request...")

    try:
        return verifier(signed_hash)
    except Exception:
        # not adding details for security
        raise HTTPException(status_code=400, detail="Not verified")
