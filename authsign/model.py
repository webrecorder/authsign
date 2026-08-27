"""Models for api"""

from datetime import datetime

from pydantic import BaseModel


class SignReq(BaseModel):
    """Sign Request consisting of hash and created date"""

    hash: str
    created: datetime


class SignedHash(SignReq):
    """Signed Hash of the SignReq, created by signer, ready for verification"""

    version: str = "0.1.0"

    software: str | None = ""

    signature: str
    domain: str
    domainCert: str
    crossSignedCert: str | None = None

    timeSignature: str
    timestampCert: str
