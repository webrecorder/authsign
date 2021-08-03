import logging

logger = logging.getLogger("signer")

RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
CHECK = "\u2713"
X = "\u2717"


def debug_assert(test, msg):
    if test:
        debug_success(msg)
    else:
        debug_failure(msg)
    assert test


def debug_message(text):
    logger.debug("  " + (COLOR_SEQ % 33) + text + RESET_SEQ)


def debug_success(text):
    logger.debug("  " + (COLOR_SEQ % 32) + CHECK + " " + text + RESET_SEQ)


def debug_failure(text):
    logger.debug("  " + (COLOR_SEQ % 31) + X + " " + text + RESET_SEQ)
