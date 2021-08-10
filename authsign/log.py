import logging

logger = logging.getLogger("authsign")

RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
CHECK = "\u2713"
X = "\u2717"


def log_assert(test, msg):
    if test:
        log_success(msg)
    else:
        log_failure(msg)
    assert test


def log_message(text):
    logger.info("  " + (COLOR_SEQ % 33) + text + RESET_SEQ)


def log_success(text):
    logger.info("  " + (COLOR_SEQ % 32) + CHECK + " " + text + RESET_SEQ)


def log_failure(text):
    logger.info("  " + (COLOR_SEQ % 31) + X + " " + text + RESET_SEQ)


def debug_error(text):
    logger.debug("  " + (COLOR_SEQ % 31) + X + " " + text + RESET_SEQ)
