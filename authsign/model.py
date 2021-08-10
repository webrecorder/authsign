from typing import Optional
from pydantic import BaseModel


class SignReq(BaseModel):
    """Sign Request consisting of hash and created date"""

    hash: str
    created: str


class SignedHash(SignReq):
    """Signed Hash of the SignReq, created by signer, ready for verification"""

    version = "0.1.0"

    software: Optional[str]

    signature: str
    domain: str
    domainCert: str
    crossSignedCert: Optional[str]

    timeSignature: str
    timestampCert: str
