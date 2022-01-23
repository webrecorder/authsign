import asyncio
import os

from fastapi import FastAPI, HTTPException, Header

from authsign.signer import Signer
from authsign.verifier import Verifier
from authsign.model import SignedHash, SignReq

from authsign.utils import load_yaml

from authsign.log import log_message, log_failure


#loop = asyncio.get_event_loop()
app = FastAPI()

signer = None
verifier = None


@app.on_event("startup")
async def startup_event():
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

    log_message("")
    log_message("Signer init...")
    signer = Signer(**config["signing"])

    if not os.environ.get("NO_RENEW"):
        asyncio.ensure_future(signer.renew_loop())

    global verifier
    log_message("")
    log_message("Verifier Init...")
    verifier = Verifier(config.get("trusted_roots"))
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
