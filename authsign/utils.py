""" shared utils """

import datetime
import importlib
import contextlib

import yaml
import dateutil.parser

# no limit on CA cert validity
YEARS = datetime.timedelta(weeks=1000)

CERT_DURATION = datetime.timedelta(days=7)

STAMP_DURATION = datetime.timedelta(minutes=10)

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def no_older_then(thedate, base, duration):
    """ensure thedate is no older than duration from base date, and also not newer"""
    if thedate > base:
        return False

    if thedate < base - duration:
        return False

    return True


def parse_date(datestr):
    """parse date using dateutil"""
    if isinstance(datestr, datetime.datetime):
        return datestr

    return dateutil.parser.parse(datestr, ignoretz=True)


def format_date(date):
    """format date to iso format"""
    return date.strftime(ISO_FORMAT)


@contextlib.contextmanager
def open_file(filename_or_resource, mode):
    """open file from either package or file system"""
    # pylint: disable=deprecated-method
    res = None
    if filename_or_resource.startswith("pkg://"):
        pkg, resource = filename_or_resource[6:].split("/", 1)
        if "b" in mode:
            res = importlib.resources.open_binary(pkg, resource)
        else:
            res = importlib.resources.open_text(pkg, resource)
    else:
        res = open(filename_or_resource, mode)

    yield res

    res.close()


def load_yaml(filename):
    """load yaml and parse to dict"""
    with open_file(filename, "rt") as fh:
        data = yaml.load(fh.read(), Loader=yaml.SafeLoader)

    return data
