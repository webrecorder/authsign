"""
Generate Cert and Pub Key via ACME
"""
from pathlib import Path

import sys
import os
import datetime
import logging

import asyncio

import certsigner.crypto as crypto

from certsigner.acme_signer import AcmeSigner
from certsigner.timesigner import TimeSigner

from certsigner.model import SignedHash

from certsigner.log import debug_verify, debug_message, debug_failure, debug_success


PASSPHRASE = b"passphrase"

AUTH = {"signing": "1"}

CERT_DURATION = datetime.timedelta(hours=12)
STAMP_DURATION = datetime.timedelta(hours=1)


class CertSigner:
    """ Signing cert, private, public key generator"""

    def __init__(
        self,
        domain=None,
        email=None,
        port=None,
        staging=True,
        output=None,
        ts_certfile=None,
        ts_url=None,
    ):
        self.domain = domain
        self.email = email
        self.port = port
        self.staging = staging

        self.rootpath = Path(output or "./data")

        self.cert_pem = None

        self.private_key = None
        self.public_key = None
        self.public_key_pem = None

        self.long_public_key = None
        self.long_public_key_pem = None
        self.long_private_key = None
        self.long_signature = None
        self.long_auth = None

        self.timesigner = TimeSigner(ts_url=ts_url, ts_certfile=ts_certfile)

        try:
            self.load_long()
        except FileNotFoundError:
            debug_message("Long-term key not found, creating new long-term key")
            self.create_long()

        res = False
        try:
            self.load_key_pair_and_cert()
            res = True
        except FileNotFoundError:
            debug_message(
                "Signing key or cert not found, creating new signing key + cert"
            )
            res = self.update_signing_key_and_cert()
        except AssertionError:
            debug_message(
                "Signing cert expired or not valid, creating new signing key + cert"
            )
            res = self.update_signing_key_and_cert()

        if not res:
            sys.exit(1)

        self.long_signature = crypto.sign(self.public_key_pem, self.long_private_key)

    def validate_token(self, auth_header):
        if not auth_header or not auth_header.startswith("bearer "):
            return False

        try:
            return AUTH == crypto.check_jwt(
                auth_header.split(" ")[1], self.long_public_key
            )
        except Exception as e:
            return False

    def load_key_pair_and_cert(self):
        """ Load key pair and cert"""
        cert = None
        debug_message("Loading: " + str(self.rootpath / "cert.pem"))
        with open(self.rootpath / "cert.pem", "rb") as fh_in:
            self.cert_pem = fh_in.read()
            cert = crypto.load_cert(self.cert_pem)

        self.public_key = cert.public_key()
        self.public_key_pem = crypto.get_public_key_pem(self.public_key)

        debug_message("Loading: " + str(self.rootpath / "public-key.pem"))
        with open(self.rootpath / "public-key.pem", "rt") as fh_in:
            data = fh_in.read()
            assert data == self.public_key_pem

        debug_message("Loading: " + str(self.rootpath / "private-key.pem"))
        with open(self.rootpath / "private-key.pem", "rb") as fh_in:
            data = fh_in.read()
            self.private_key = crypto.load_private_key(data, PASSPHRASE)

        now = datetime.datetime.utcnow()

        try:
            debug_verify("Validating key pair")
            assert self.test_keys("Data Signature Test")

            debug_verify("Validating cert still valid")
            assert self.is_cert_time_valid(cert, now)

            debug_verify(True)
        except:
            debug_verify(False)
            raise

        self.set_next_update_time(cert)

    def set_next_update_time(self, cert):
        next_update = cert.not_valid_before + CERT_DURATION
        debug_message(
            "Certificate will be used from {0} to {1}".format(
                cert.not_valid_before, next_update
            )
        )
        next_update = (next_update - datetime.datetime.utcnow()).total_seconds()
        self.next_update = next_update

    def is_cert_time_valid(self, cert, thedate):
        return (
            cert.not_valid_before < thedate
            and thedate - cert.not_valid_before < CERT_DURATION
        )

    def test_keys(self, data):
        """ Test key pair sign/verify to ensure its valid """
        signature = crypto.sign(data, self.private_key)
        return crypto.verify(data, signature, self.public_key)

    def save_key_pair_and_cert(self):
        """ Save keypair and cert """
        debug_message("Saving: " + str(self.rootpath / "private-key.pem"))
        with open(self.rootpath / "private-key.pem", "wb") as fh_out:
            fh_out.write(crypto.save_private_key(self.private_key, PASSPHRASE))

        debug_message("Saving: " + str(self.rootpath / "public-key.pem"))
        with open(self.rootpath / "public-key.pem", "wt") as fh_out:
            fh_out.write(self.public_key_pem)

        debug_message("Saving: " + str(self.rootpath / "cert.pem"))
        with open(self.rootpath / "cert.pem", "wt") as fh_out:
            fh_out.write(self.cert_pem)

    def load_long(self):
        """ Load long-term key pair """
        debug_message("Loading: " + str(self.rootpath / "long-public-key.pem"))
        with open(self.rootpath / "long-public-key.pem", "rb") as fh_in:
            data = fh_in.read()
            self.long_public_key = crypto.load_public_key(data)
            self.long_public_key_pem = crypto.get_public_key_pem(self.long_public_key)

        debug_message("Loading: " + str(self.rootpath / "long-private-key.pem"))
        with open(self.rootpath / "long-private-key.pem", "rb") as fh_in:
            data = fh_in.read()
            self.long_private_key = crypto.load_private_key(data, PASSPHRASE)

    def create_long(self):
        """ Create long-term key pair """
        self.rootpath.mkdir(exist_ok=True)

        self.long_private_key = crypto.create_ecdsa_private_key()

        debug_message("Saving: " + str(self.rootpath / "long-private-key.pem"))
        with open(self.rootpath / "long-private-key.pem", "wb") as fh_out:
            fh_out.write(crypto.save_private_key(self.long_private_key, PASSPHRASE))

        self.long_public_key = self.long_private_key.public_key()
        self.long_public_key_pem = crypto.get_public_key_pem(self.long_public_key)

        debug_message("Saving: " + str(self.rootpath / "long-public-key.pem"))
        with open(self.rootpath / "long-public-key.pem", "wt") as fh_out:
            fh_out.write(crypto.get_public_key_pem(self.long_public_key))

        debug_message("Saving: " + str(self.rootpath / "auth-token.txt"))
        with open(self.rootpath / "auth-token.txt", "wt") as fh_out:
            fh_out.write(crypto.create_jwt(AUTH, self.long_private_key))

    def update_signing_key_and_cert(self):
        """ Run cert creation"""
        self.private_key = crypto.create_ecdsa_private_key()

        self.public_key = self.private_key.public_key()
        self.public_key_pem = crypto.get_public_key_pem(self.public_key)

        csr_pem = crypto.create_csr(self.domain, self.private_key)

        debug_message("Awaiting new cert for domain: " + self.domain)

        signer = AcmeSigner(self.domain, self.email, self.port, self.staging)

        try:
            self.cert_pem = signer.get_acme_cert(csr_pem)
            debug_success("Obtained new domain cert for: " + self.domain)
        except Exception as e:
            debug_failure("Unable to retrieve cert for: " + self.domain)
            debug_failure("Reason: " + repr(e))
            return False

        self.save_key_pair_and_cert()
        self.set_next_update_time(crypto.load_cert(self.cert_pem.encode("ascii")))
        return True

    def sign_request(self, hash_):
        now = datetime.datetime.utcnow().isoformat()

        signature = crypto.sign(hash_, self.private_key)

        time_signature = self.timesigner.sign(hash_)

        return SignedHash(
            hash=hash_,
            date=now,
            signature=signature,
            publicKey=self.public_key_pem,
            timeSignature=time_signature,
            domainCert=self.cert_pem,
            timestampCert=self.timesigner.cert_pem,
            longSignature=self.long_signature,
            longPublicKey=self.long_public_key_pem,
        )

    def verify_request(self, signed_req):
        """ Verify signed hash request """

        try:
            debug_verify("Verify signature of hash with public key")
            public_key = crypto.load_public_key(signed_req.publicKey.encode("ascii"))
            assert crypto.verify(signed_req.hash, signed_req.signature, public_key)

            if signed_req.longSignature and signed_req.longPublicKey:
                debug_verify(
                    "Verify longSignature is a signature of publicKey via longPublicKey"
                )
                long_public_key = crypto.load_public_key(
                    signed_req.longPublicKey.encode("ascii")
                )
                assert crypto.verify(
                    signed_req.publicKey, signed_req.longSignature, long_public_key
                )

            created = datetime.datetime.strptime(
                signed_req.date[:19], "%Y-%m-%dT%H:%M:%S"
            )

            # parse each cert in chain and validate signature using the next cert, returning first cert if valid
            debug_verify("Validate certificate chain for domain certificate")
            cert = crypto.validate_cert_chain(signed_req.domainCert.encode("ascii"))
            assert cert

            debug_verify(
                "Verify domain certificate was created within one hour of creation date"
            )
            assert self.is_cert_time_valid(cert, created)

            debug_verify(
                "Verify timestamp signature and creation within one hour of creation date"
            )
            assert self.timesigner.verify(
                signed_req.hash, signed_req.timeSignature, created, STAMP_DURATION
            )

            debug_verify("Validate certificate chan for timestamp certificate")
            assert crypto.validate_cert_chain(signed_req.timestampCert.encode("ascii"))

            debug_verify(True)
            return {"domain": crypto.get_cert_subject_name(cert)}

        except:
            debug_verify(False)
            return False

    async def renew_loop(self, loop):
        debug_message(
            "Renewing domain certificate in {0} seconds".format(self.next_update)
        )
        await asyncio.sleep(self.next_update)
        update_time = CERT_DURATION.total_seconds()

        while True:
            debug_message("Running domain certificate update...")
            await loop.run_in_executor(None, self.update_signing_key_and_cert())
            debug_message("Done, next update in {0} seconds".format(update_time))
            await asyncio.sleep(update_time)
