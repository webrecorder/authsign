"""multicolored logging utils"""

from typing import TypeVar
import logging

logger = logging.getLogger("authsign")

RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
CHECK = "\u2713"
X = "\u2717"


# pylint: disable=logging-not-lazy
T = TypeVar("T")


def log_assert(test: T | None, msg) -> T:
    """log and raise assertion error"""
    if test:
        log_success(msg)
    else:
        log_failure(msg)
    assert test
    return test


def log_message(text: str) -> None:
    """log message in neutral color"""
    logger.info("  " + (COLOR_SEQ % 33) + text + RESET_SEQ)


def log_success(text: str) -> None:
    """log message in success color"""
    logger.info("  " + (COLOR_SEQ % 32) + CHECK + " " + text + RESET_SEQ)


def log_failure(text: str) -> None:
    """log message in failure color"""
    logger.info("  " + (COLOR_SEQ % 31) + X + " " + text + RESET_SEQ)


def debug_error(text: str) -> None:
    """log message at debugging level in failure color"""
    logger.debug("  " + (COLOR_SEQ % 31) + X + " " + text + RESET_SEQ)
