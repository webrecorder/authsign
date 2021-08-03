import logging

logger = logging.getLogger("signer")

RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
CHECK = "\u2713"
X = "\u2717"

prev_msg = None


def debug_verify(msg):
    global prev_msg
    if prev_msg and msg:
        debug_success(prev_msg)

    if msg == True:
        prev_msg = None
    elif msg == False:
        if prev_msg:
            debug_failure(prev_msg)
    else:
        prev_msg = msg


def debug_message(text):
    logger.debug("  " + (COLOR_SEQ % 33) + text + RESET_SEQ)


def debug_success(text):
    logger.debug("  " + (COLOR_SEQ % 32) + CHECK + " " + text + RESET_SEQ)


def debug_failure(text):
    logger.debug("  " + (COLOR_SEQ % 31) + X + " " + text + RESET_SEQ)
