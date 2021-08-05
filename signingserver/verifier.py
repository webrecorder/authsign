""" Verify signed requests"""


import base64
import datetime
import rfc3161ng

import signingserver.crypto as crypto
from signingserver.model import CERT_DURATION, STAMP_DURATION, is_time_range_valid, parse_date
from signingserver.log import debug_assert, debug_message


# ============================================================================
class Verifier:
    def __init__(self, trusted_roots):
        self.domain_cert_roots = trusted_roots["domain_cert_roots"]
        self.timestamp_cert_roots = trusted_roots["timestamp_cert_roots"]

        debug_message("{0} Domain Cert Root(s) Loaded".format(len(self.domain_cert_roots)))
        debug_message("{0} Timestamp Cert Root(s) Loaded".format(len(self.timestamp_cert_roots)))

    def timestamp_verify(self, text, signature, cert_pem):
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

    def check_fingerprint(self, cert, trusted, name):
        """ Check if cert fingerprint matches one of trusted fingerprints (sha-256 hashes)"""
        fingerprint = crypto.get_fingerprint(cert)

        debug_assert(fingerprint in trusted, "Trusted {0} Root Cert (sha-256 fingerprint: {1})".format(name, fingerprint))

    def verify_request(self, signed_req):
        """ Verify signed hash request """

        try:
            # parse each cert in chain and validate signature using the next cert, returning first cert if valid
            certs = crypto.validate_cert_chain(signed_req.domainCert.encode("ascii"))
            debug_assert(certs, "Verify certificate chain for domain certificate")
            cert = certs[0]

            self.check_fingerprint(certs[-1], self.domain_cert_roots, "Domain")

            public_key = cert.public_key()
            debug_assert(
                crypto.verify(signed_req.hash, signed_req.signature, public_key),
                "Verify signature of hash with public key from domain certificate",
            )

            domain = crypto.get_cert_subject_name(cert)

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

            created = parse_date(signed_req.date)
            debug_assert(created, "Parsed signature date")

            debug_assert(
                is_time_range_valid(cert.not_valid_before, created, CERT_DURATION),
                "Verify domain certificate was created within {0} creation date".format(
                    str(CERT_DURATION)
                ),
            )

            timestamp = self.timestamp_verify(
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

            timestamp_certs = crypto.validate_cert_chain(
                signed_req.timestampCert.encode("ascii")
            )

            debug_assert(
                timestamp_certs, "Verify certificate chain for timestamp certificate"
            )

            self.check_fingerprint(timestamp_certs[-1], self.timestamp_cert_roots, "Timestamp")

            return {"domain": domain}

        except:
            return False
