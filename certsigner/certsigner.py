"""
Generate Cert and Pub Key via ACME
"""
from pathlib import Path

import datetime
import logging
import base64

import certsigner.crypto as crypto

from certsigner.acme_signer import AcmeSigner

from pyasn1.codec.der import encoder
import rfc3161ng

# logger = logging.getLogger("signer")
# logger.setLevel(logging.INFO)
logger = logging.getLogger("api")


PASSPHRASE = b"passphrase"

AUTH = {"signing": "1"}


class CertSigner:
    """ Signing cert, private, public key generator"""

    def __init__(self, domain=None, email=None, port=None, staging=True, output=None, ts_cert=None, ts_url=None):
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

        self.ts_url = ts_url
        self.ts_cert = ts_cert
        self.time_stamper = None

    def init_timestamper(self):
        with open(self.ts_cert, "rb") as fh_in:
            cert = fh_in.read()

        self.time_stamper = rfc3161ng.RemoteTimestamper(
            self.ts_url, certificate=cert, hashname="sha256"
        )

    def timestamp_sign(self, text):
        tsr = self.time_stamper(data=text.encode("ascii"), return_tsr=True)

        result = encoder.encode(tsr)

        return base64.b64encode(result)

    def validate_token(self, auth_header):
        if not auth_header or not auth_header.startswith("bearer "):
            return False

        try:
            return AUTH == crypto.check_jwt(
                auth_header.split(" ")[1], self.long_public_key
            )
        except Exception as e:
            print(e)
            return False

    def load_key_pair_and_cert(self):
        """ Load key pair and cert"""
        cert = None
        with open(self.rootpath / "cert.pem", "rb") as fh_in:
            self.cert_pem = fh_in.read()
            cert = crypto.load_cert(self.cert_pem)

        self.public_key = cert.public_key()
        self.public_key_pem = crypto.get_public_key_pem(self.public_key)

        with open(self.rootpath / "public-key.pem", "rt") as fh_in:
            data = fh_in.read()
            assert data == self.public_key_pem

        with open(self.rootpath / "private-key.pem", "rb") as fh_in:
            data = fh_in.read()
            self.private_key = crypto.load_private_key(data, PASSPHRASE)

        assert self.test_keys("Data Signature Test")

        assert datetime.datetime.now() - cert.not_valid_before < datetime.timedelta(
            hours=12
        )

    def test_keys(self, data):
        """ Test key pair sign/verify to ensure its valid """
        signature = crypto.sign(data, self.private_key)
        return crypto.verify(data, signature, self.public_key)

    def save_key_pair_and_cert(self):
        """ Save keypair and cert """
        with open(self.rootpath / "private-key.pem", "wb") as fh_out:
            fh_out.write(crypto.save_private_key(self.private_key, PASSPHRASE))

        with open(self.rootpath / "public-key.pem", "wt") as fh_out:
            fh_out.write(self.public_key_pem)

        with open(self.rootpath / "cert.pem", "wt") as fh_out:
            fh_out.write(self.cert_pem)

    def load_long(self):
        """ Load long-term key pair """
        with open(self.rootpath / "long-public-key.pem", "rb") as fh_in:
            data = fh_in.read()
            self.long_public_key = crypto.load_public_key(data)
            self.long_public_key_pem = crypto.get_public_key_pem(self.long_public_key)

        with open(self.rootpath / "long-private-key.pem", "rb") as fh_in:
            data = fh_in.read()
            self.long_private_key = crypto.load_private_key(data, PASSPHRASE)

    def create_long(self):
        """ Create long-term key pair """
        self.rootpath.mkdir(exist_ok=True)

        self.long_private_key = crypto.create_ecdsa_private_key()

        with open(self.rootpath / "long-private-key.pem", "wb") as fh_out:
            fh_out.write(crypto.save_private_key(self.long_private_key, PASSPHRASE))

        self.long_public_key = self.long_private_key.public_key()
        self.long_public_key_pem = crypto.get_public_key_pem(self.long_public_key)

        with open(self.rootpath / "long-public-key.pem", "wt") as fh_out:
            fh_out.write(crypto.get_public_key_pem(self.long_public_key))

        with open(self.rootpath / "auth-token.txt", "wt") as fh_out:
            fh_out.write(crypto.create_jwt(AUTH, self.long_private_key))

    def init(self):
        self.init_timestamper()
        try:
            self.load_long()
        except FileNotFoundError:
            logger.info("Long-term key not found, creating new long-term key")
            self.create_long()

        try:
            self.load_key_pair_and_cert()
        except FileNotFoundError:
            logger.info(
                "Signing key or cert not found, creating new signing key + cert"
            )
            self.update_signing_key_and_cert()
        except AssertionError:
            logger.info(
                "Signing cert expired or not valid, creating new signing key + cert"
            )
            self.update_signing_key_and_cert()

        self.long_signature = crypto.sign(self.public_key_pem, self.long_private_key)

    def update_signing_key_and_cert(self):
        """ Run cert creation"""
        self.private_key = crypto.create_ecdsa_private_key()

        self.public_key = self.private_key.public_key()
        self.public_key_pem = crypto.get_public_key_pem(self.public_key)

        # self.long_signature = crypto.sign(self.public_key_pem, self.long_private_key)

        csr_pem = crypto.create_csr(self.domain, self.private_key)

        signer = AcmeSigner(self.domain, self.email, self.port, self.staging)
        self.cert_pem = signer.get_acme_cert(csr_pem)

        self.save_key_pair_and_cert()

    def sign_request(self, data):
        signature = crypto.sign(data, self.private_key)

        timeSignature = self.timestamp_sign(data)

        return {
            "signature": signature,
            "publicKey": self.public_key_pem,
            "longSignature": self.long_signature,
            "longPublicKey": self.long_public_key_pem,
            "timeSignature": self.timestamp_sign(data),
            "domainCert": self.cert_pem,
        }
