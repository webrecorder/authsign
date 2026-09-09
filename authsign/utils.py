"""shared utils"""

import datetime
import importlib
import contextlib
from typing import TextIO
from collections.abc import Generator

import yaml

# no limit on CA cert validity
YEARS = datetime.timedelta(weeks=1000)

CERT_DURATION = datetime.timedelta(days=7)

STAMP_DURATION = datetime.timedelta(minutes=10)

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def no_older_then(
    thedate: datetime.datetime, base: datetime.datetime, duration: datetime.timedelta
) -> bool:
    """ensure thedate is no older than duration from base date, and also not newer"""
    if thedate > base:
        return False

    if thedate < base - duration:
        return False

    return True


def format_date(date: datetime.datetime) -> str:
    """format date to iso format"""
    return date.strftime(ISO_FORMAT)


@contextlib.contextmanager
def open_file(filename_or_resource: str) -> Generator[TextIO]:
    """open text file from either package or file system"""
    if filename_or_resource.startswith("pkg://"):
        pkg, resource = filename_or_resource[6:].split("/", 1)
        res = importlib.resources.open_text(pkg, resource)
    else:
        res = open(filename_or_resource, "rt")

    yield res

    res.close()


def load_yaml(filename: str) -> dict:
    """load yaml and parse to dict"""
    with open_file(filename) as fh:
        data = yaml.load(fh.read(), Loader=yaml.SafeLoader)

    return data
