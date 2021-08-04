""" Verify signed requests"""


import base64
import datetime
import rfc3161ng

import signingserver.crypto as crypto
from signingserver.model import CERT_DURATION, STAMP_DURATION, is_time_range_valid
from signingserver.log import debug_assert, debug_message


# ============================================================================
def timestamp_verify(text, signature, cert_pem):
    resp = rfc3161ng.decode_timestamp_response(base64.b64decode(signature))
    tst = resp.time_stamp_token

    # verify timestamp was signed by the existing cert
    try:
        rfc3161ng.check_timestamp(
            tst,
            certificate=cert_pem.encode("ascii"),
            data=text.encode("ascii"),
            hashname="sha256",
        )
    except Exception as e:
        return None

    return rfc3161ng.get_timestamp(tst)


# ============================================================================
def verify_request(signed_req):
    """ Verify signed hash request """

    try:
        # parse each cert in chain and validate signature using the next cert, returning first cert if valid
        cert = crypto.validate_cert_chain(signed_req.domainCert.encode("ascii"))
        debug_assert(cert, "Verify certificate chain for domain certificate")

        # public_key = crypto.load_public_key(signed_req.publicKey.encode("ascii"))
        public_key = cert.public_key()
        debug_assert(
            crypto.verify(signed_req.hash, signed_req.signature, public_key),
            "Verify signature of hash with public key from domain certificate",
        )

        if signed_req.longSignature and signed_req.longPublicKey:
            long_public_key = crypto.load_public_key(
                signed_req.longPublicKey.encode("ascii")
            )
            debug_assert(
                crypto.verify(
                    crypto.get_public_key_pem(public_key),
                    signed_req.longSignature,
                    long_public_key,
                ),
                "Verify longSignature is a signature of public key via longPublicKey",
            )

        created = datetime.datetime.strptime(signed_req.date[:19], "%Y-%m-%dT%H:%M:%S")

        debug_assert(
            is_time_range_valid(cert.not_valid_before, created, CERT_DURATION),
            "Verify domain certificate was created within {0} creation date".format(
                str(CERT_DURATION)
            ),
        )

        timestamp = timestamp_verify(
            signed_req.signature, signed_req.timeSignature, signed_req.timestampCert
        )

        debug_assert(
            timestamp,
            "Verify timeSignature is valid timestamp signature of hash signature with timestamp certificate",
        )

        debug_assert(
            is_time_range_valid(created, timestamp, STAMP_DURATION),
            "Verify time signature created within {0} hour of creation date".format(
                str(STAMP_DURATION)
            ),
        )

        timestamp_cert = crypto.validate_cert_chain(
            signed_req.timestampCert.encode("ascii")
        )
        debug_assert(
            timestamp_cert, "Verify certificate chain for timestamp certificate"
        )

        debug_message("Domain Cert Fingerprint: " + crypto.get_fingerprint(cert))
        debug_message("Timestamp Cert Fingerprint: " + crypto.get_fingerprint(timestamp_cert))

        return {"domain": crypto.get_cert_subject_name(cert)}

    except:
        return False
