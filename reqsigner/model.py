from pydantic import BaseModel
from typing import Optional


class SignedHash(BaseModel):
    hash: str
    signature: str
    date: str
    publicKey: str
    timeSignature: str
    domainCert: str
    timestampCert: str

    longSignature: Optional[str]
    longPublicKey: Optional[str]
