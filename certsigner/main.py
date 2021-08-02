import asyncio
import os

import yaml

from fastapi import FastAPI, HTTPException, Response, Header

from certsigner.certsigner import CertSigner

loop = asyncio.get_event_loop()

app = FastAPI()


def get_config():
    configfile = os.environ.get("CONFIG", "config.yaml")
    with open(configfile, "rt") as fh:
        data = yaml.load(fh.read())

    print(data)
    return data["config"]

updater = CertSigner(**get_config())
updater.init()


async def updater_loop():
    while True:
        await asyncio.sleep(43200)
        print("Running Cert Update")
        await loop.run_in_executor(None, updater.update_signing_key_and_cert())


task = loop.create_task(updater_loop())


@app.post("/sign/{data}")
async def sign_data(data, authorization: str = Header(None)):
    if not updater.validate_token(authorization):
        raise HTTPException(status_code=403, detail="Invalid auth token")

    return updater.sign_request(data)
