import asyncio
import os

import yaml

from fastapi import FastAPI, HTTPException, Header

from certsigner.certsigner import CertSigner
from certsigner.model import SignedHash


loop = asyncio.get_event_loop()

app = FastAPI()


def get_config():
    configfile = os.environ.get("CONFIG", "config.yaml")
    with open(configfile, "rt") as fh:
        data = yaml.load(fh.read())

    print(data)
    return data["config"]


updater = CertSigner(**get_config())


async def updater_loop():
    while True:
        await asyncio.sleep(43200)
        print("Running Cert Update")
        await loop.run_in_executor(None, updater.update_signing_key_and_cert())


task = loop.create_task(updater_loop())


@app.post("/sign/{data}", response_model=SignedHash)
async def sign_data(data, authorization: str = Header(None)):
    if not updater.validate_token(authorization):
        raise HTTPException(status_code=403, detail="Invalid auth token")

    return updater.sign_request(data)


@app.post("/verify")
async def verify_data(signed_req: SignedHash):
    result = await loop.run_in_executor(None, updater.verify_request, signed_req)
    if result:
        return result

    raise HTTPException(status_code=400, detail="Not verified")
