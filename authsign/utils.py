import datetime
import importlib
import contextlib

import yaml


CERT_DURATION = datetime.timedelta(hours=48)
STAMP_DURATION = datetime.timedelta(hours=1)


def is_time_range_valid(base, thedate, duration):
    return base <= thedate and thedate - base <= duration


def parse_date(datestr):
    try:
        return datetime.datetime.strptime(datestr, "%Y-%m-%dT%H:%M:%SZ")
    except:
        return None


def format_date(date):
    return date.strftime("%Y-%m-%dT%H:%M:%SZ")


@contextlib.contextmanager
def open_file(filename_or_resource, mode):
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
    with open_file(filename, "rt") as fh:
        data = yaml.load(fh.read(), Loader=yaml.SafeLoader)

    return data