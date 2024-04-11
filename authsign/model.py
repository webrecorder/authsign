""" Models for api """

from typing import Optional
from datetime import datetime

from pydantic import BaseModel, validator

from authsign.utils import parse_date, format_date


class SignReq(BaseModel):
    """Sign Request consisting of hash and created date"""

    hash: str
    created: datetime

    # pylint: disable=no-self-argument
    @validator("created", pre=True)
    def dt_validate(cls, dt):
        """parse using dateutil if string"""
        return parse_date(dt)

    # pylint: disable=too-few-public-methods
    class Config:
        """custom serializer for datetime"""

        json_encoders = {datetime: format_date}


class SignedHash(SignReq):
    """Signed Hash of the SignReq, created by signer, ready for verification"""

    version: str = "0.1.0"

    software: Optional[str]

    signature: str
    domain: str
    domainCert: str
    crossSignedCert: Optional[str]

    timeSignature: str
    timestampCert: str
