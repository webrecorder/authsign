"""
Generate Cert and Pub Key via ACME
"""
from pathlib import Path

import datetime
import base64
import random
import asyncio

from pyasn1.codec.der import encoder
import rfc3161ng

import signingserver.crypto as crypto

from signingserver.acme_signer import AcmeSigner

from signingserver.model import SignedHash, CERT_DURATION, is_time_range_valid, format_date

from signingserver.log import debug_assert, debug_message, debug_failure, debug_success


PASSPHRASE = b"passphrase"

AUTH = {"signing": "1"}

renewing = False


# ============================================================================
class Timestamper:
    def __init__(self, certfile=None, url=None):
        self.cert_pem = None
        with open(certfile, "rb") as fh_in:
            self.cert_pem = fh_in.read()

        self._timestamper = rfc3161ng.RemoteTimestamper(
            url, certificate=self.cert_pem, hashname="sha256"
        )

    def sign(self, text):
        tsr = self._timestamper(data=text.encode("ascii"), return_tsr=True)

        result = encoder.encode(tsr)

        return base64.b64encode(result)


# ============================================================================
class Signer:
    """ Signing cert, private, public key generator"""

    def __init__(
        self,
        domain=None,
        email=None,
        port=None,
        staging=True,
        output=None,
        timestamping=None
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

        self.next_update = 0

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
            raise Exception("Could not load domain signing cert + keys")

        self.long_signature = crypto.sign(self.public_key_pem, self.long_private_key)

        self.timestampers = [Timestamper(**ts_data) for ts_data in timestamping]

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

        debug_message("Loading: " + str(self.rootpath / "private-key.pem"))
        with open(self.rootpath / "private-key.pem", "rb") as fh_in:
            data = fh_in.read()
            self.private_key = crypto.load_private_key(data, PASSPHRASE)

        now = datetime.datetime.utcnow()

        debug_assert(self.test_keys("Data Signature Test"), "Validating key pair")

        debug_assert(
            is_time_range_valid(cert.not_valid_before, now, CERT_DURATION),
            "Validating cert still valid",
        )

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

    def test_keys(self, data):
        """ Test key pair sign/verify to ensure its valid """
        signature = crypto.sign(data, self.private_key)
        return crypto.verify(data, signature, self.public_key)

    def save_key_pair_and_cert(self):
        """ Save keypair and cert """
        debug_message("Saving: " + str(self.rootpath / "private-key.pem"))
        with open(self.rootpath / "private-key.pem", "wb") as fh_out:
            fh_out.write(crypto.save_private_key(self.private_key, PASSPHRASE))

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
        now = format_date(datetime.datetime.utcnow())

        signature = crypto.sign(hash_, self.private_key)

        timestamper = random.choice(self.timestampers)

        time_signature = timestamper.sign(signature)

        return SignedHash(
            hash=hash_,
            date=now,
            signature=signature,
            # publicKey=self.public_key_pem,
            timeSignature=time_signature,
            domainCert=self.cert_pem,
            timestampCert=timestamper.cert_pem,
            longSignature=self.long_signature,
            longPublicKey=self.long_public_key_pem,
        )

    async def renew_loop(self):
        debug_message(
            "Renewing domain certificate in {0}".format(datetime.timedelta(seconds=self.next_update))
        )
        loop = asyncio.get_event_loop()
        await asyncio.sleep(self.next_update)
        update_time = CERT_DURATION.total_seconds()
        global renewing

        while True:
            debug_message("Running domain certificate update...")
            renewing = True
            await loop.run_in_executor(None, self.update_signing_key_and_cert)
            debug_message("Done, next update in {0}".format(datetime.timedelta(seconds=update_time)))
            renewing = False
            await asyncio.sleep(update_time)
