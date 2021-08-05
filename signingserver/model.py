import datetime
from typing import Optional
from pydantic import BaseModel


CERT_DURATION = datetime.timedelta(hours=48)
STAMP_DURATION = datetime.timedelta(hours=1)


class SignedHash(BaseModel):
    hash: str
    signature: str
    date: str
    # publicKey: str
    timeSignature: str
    domainCert: str
    timestampCert: str

    longSignature: Optional[str]
    longPublicKey: Optional[str]


def is_time_range_valid(base, thedate, duration):
    return base <= thedate and thedate - base <= duration


def parse_date(datestr):
    try:
        return datetime.datetime.strptime(datestr, "%Y-%m-%dT%H:%M:%SZ")
    except:
        return None


def format_date(date):
    return date.strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


