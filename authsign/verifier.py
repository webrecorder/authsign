""" Verify signed responses api"""


import base64
import traceback

import rfc3161ng

from authsign.utils import (
    CERT_DURATION,
    STAMP_DURATION,
    is_time_range_valid,
    parse_date,
    load_yaml,
)
from authsign import crypto
from authsign.log import log_assert, log_message, debug_error
from authsign.model import SignedHash
from authsign.utils import format_date


DEFAULT_TRUSTED_ROOTS = "pkg://authsign.trusted/roots.yaml"


# ============================================================================
class Verifier:
    """Verifies signed response from signer to check for validity"""

    def __init__(self, trusted_roots_filename=None):
        trusted_roots_filename = trusted_roots_filename or DEFAULT_TRUSTED_ROOTS
        log_message("Loading trusted roots from: " + trusted_roots_filename)
        trusted_roots = load_yaml(trusted_roots_filename)

        self.domain_cert_roots = trusted_roots["domain_cert_roots"]
        self.timestamp_cert_roots = trusted_roots["timestamp_cert_roots"]

        log_message(
            "{0} Domain Cert Root(s) Loaded".format(len(self.domain_cert_roots))
        )
        log_message(
            "{0} Timestamp Cert Root(s) Loaded".format(len(self.timestamp_cert_roots))
        )

    def timestamp_verify(self, text, signature, cert_pem):
        """Verify RFC 3161 timestamp given a cert, signature and text
        Return the timestamp"""
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
        except Exception:
            debug_error(traceback.format_exc())
            return None

        return rfc3161ng.get_timestamp(tst)

    def check_fingerprint(self, cert, trusted, name):
        """Check if cert fingerprint matches one of trusted fingerprints (sha-256 hashes)"""
        fingerprint = crypto.get_fingerprint(cert)

        log_assert(
            fingerprint in trusted,
            "Trusted {0} Root Cert (sha-256 fingerprint: {1})".format(
                name, fingerprint
            ),
        )

    def __call__(self, signed_req):
        """Verify signed hash request"""

        if isinstance(signed_req, dict):
            signed_req = SignedHash(**signed_req)

        try:
            log_message("Signing Software: " + str(signed_req.software))

            certs = crypto.validate_cert_chain(signed_req.domainCert.encode("ascii"))
            log_assert(certs, "Verify certificate chain for domain certificate")
            cert = certs[0]

            self.check_fingerprint(certs[-1], self.domain_cert_roots, "Domain")

            public_key = cert.public_key()
            log_assert(
                crypto.verify(signed_req.hash, signed_req.signature, public_key),
                "Verify signature of hash with public key from domain certificate",
            )

            if signed_req.crossSignedCert:
                cs_certs = crypto.validate_cert_chain(
                    signed_req.crossSignedCert.encode("ascii")
                )
                log_assert(
                    cs_certs, "Verify certificate chain for cross-signed certificate"
                )
                cs_public_key = cs_certs[0].public_key()

                log_assert(
                    crypto.verify(signed_req.hash, signed_req.signature, cs_public_key),
                    "Verify signature of hash with public key of cross-signed certificate",
                )

            domain = crypto.get_cert_subject_name(cert)
            log_assert(
                domain == signed_req.domain, "Domain Cert Matches Expected: " + domain
            )

            created = parse_date(signed_req.created)
            log_assert(created, "Parsed signature date")

            log_assert(
                is_time_range_valid(cert.not_valid_before, created, CERT_DURATION),
                "Verify domain certificate was created within '{0}' of creation date".format(
                    str(CERT_DURATION)
                ),
            )

            timestamp = self.timestamp_verify(
                signed_req.signature, signed_req.timeSignature, signed_req.timestampCert
            )

            log_assert(
                timestamp,
                "Verify timeSignature is a valid timestamp signature of\
 hash signature with timestamp certificate",
            )

            log_assert(
                is_time_range_valid(created, timestamp, STAMP_DURATION),
                "Verify time signature created within '{0}' of creation date".format(
                    str(STAMP_DURATION)
                ),
            )

            timestamp_certs = crypto.validate_cert_chain(
                signed_req.timestampCert.encode("ascii")
            )

            log_assert(
                timestamp_certs, "Verify certificate chain for timestamp certificate"
            )

            self.check_fingerprint(
                timestamp_certs[-1], self.timestamp_cert_roots, "Timestamp"
            )

            return {"observer": domain, "timestamp": format_date(timestamp)}

        except Exception:
            debug_error(traceback.format_exc())
            return None
