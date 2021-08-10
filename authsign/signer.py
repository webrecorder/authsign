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


from authsign import crypto, __version__

from authsign.acme_signer import AcmeSigner

from authsign.model import SignedHash
from authsign.utils import (
    CERT_DURATION,
    STAMP_DURATION,
    YEARS,
    parse_date,
    is_time_range_valid,
    open_file,
)

from authsign.log import log_assert, log_message, log_failure, log_success


PASSPHRASE = b"passphrase"

renewing = False


# ============================================================================
class Timestamper:
    def __init__(self, certfile=None, url=None):
        self.cert_pem = None
        with open_file(certfile, "rb") as fh_in:
            self.cert_pem = fh_in.read()

        self._timestamper = rfc3161ng.RemoteTimestamper(
            url, certificate=self.cert_pem, hashname="sha256"
        )

    def __call__(self, text):
        tsr = self._timestamper(data=text.encode("ascii"), return_tsr=True)

        tst = tsr.time_stamp_token

        result = encoder.encode(tsr)

        return base64.b64encode(result), rfc3161ng.get_timestamp(tst)


# ============================================================================
class CertKeyPair:
    """Loads a cert + private key from PEM, extracts public key from cert"""

    def __init__(self):
        self.cert_pem = None
        self.cert = None

        self.public_key = None
        self.public_key_pem = None

        self.private_key = None

    def load(
        self, name, certfile, private_key, passphrase=PASSPHRASE, duration=CERT_DURATION
    ):
        log_message("{0}: Loading Cert: {1}".format(name, str(certfile)))
        with open(certfile, "rb") as fh_in:
            self.set_cert(fh_in.read())

        self.public_key = self.cert.public_key()
        self.public_key_pem = crypto.get_public_key_pem(self.public_key)

        log_message("{0}: Loading Private Key: {1}".format(name, str(private_key)))
        with open(private_key, "rb") as fh_in:
            data = fh_in.read()
            self.private_key = crypto.load_private_key(data, passphrase)

        now = datetime.datetime.utcnow()

        log_assert(self.test_keys("Data Signature Test"), "Validating key pair")

        log_assert(
            is_time_range_valid(self.cert.not_valid_before, now, duration)
            and now <= self.cert.not_valid_after,
            "Validating cert still valid",
        )

        return self

    def init_new(self):
        self.private_key = crypto.create_ecdsa_private_key()

        self.public_key = self.private_key.public_key()
        self.public_key_pem = crypto.get_public_key_pem(self.public_key)

        return self

    def set_cert(self, cert_pem):
        self.cert_pem = cert_pem
        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode("ascii")
        self.cert = crypto.load_cert(cert_pem)

    def test_keys(self, data):
        """Test key pair sign/verify to ensure its valid"""
        signature = crypto.sign(data, self.private_key)
        return crypto.verify(data, signature, self.public_key)


# ============================================================================
class Signer:
    """Signing cert, private, public key generator"""

    def __init__(
        self,
        domain=None,
        email=None,
        port=None,
        staging=True,
        output=None,
        timestamping=None,
        auth_token=None,
        csca_cert=None,
        csca_private_key=None,
    ):
        self.domain = domain
        self.email = email
        self.port = port
        self.staging = staging

        self.auth_token = auth_token

        log_message("Accepting Auth Token: " + str(self.auth_token))

        self.rootpath = Path(output or "./data")
        self.rootpath.mkdir(exist_ok=True)

        if csca_cert and csca_private_key:
            self.csca_signing = CertKeyPair().load(
                "Cross-Signing",
                csca_cert,
                csca_private_key,
                passphrase=None,
                duration=YEARS,
            )
        else:
            self.csca_signing = None

        self.next_update = 0

        self.domain_signing = None

        self.cs_cert_pem = None

        try:
            self.load_key_pair_and_cert()
        except FileNotFoundError:
            log_message(
                "Signing key or cert not found, creating new signing key + cert"
            )
            self.update_signing_key_and_cert()
        except AssertionError:
            log_message(
                "Signing cert expired or not valid, creating new signing key + cert"
            )
            self.update_signing_key_and_cert()

        if not self.domain_signing:
            raise Exception("Could not load domain signing cert + keys")

        self.timestampers = [Timestamper(**ts_data) for ts_data in timestamping]

    def validate_token(self, auth_header):
        if not self.auth_token:
            return True

        if not auth_header or not auth_header.startswith("bearer "):
            return False

        return auth_header.split(" ")[1] == self.auth_token

    def load_key_pair_and_cert(self):
        """Load key pair and cert"""

        self.domain_signing = CertKeyPair().load(
            "Domain Auth", self.rootpath / "cert.pem", self.rootpath / "private-key.pem"
        )

        self.set_next_update_time(self.domain_signing.cert)

        if self.csca_signing:
            cross_signing = CertKeyPair().load(
                "Cross-Signing Cert",
                self.rootpath / "cs-cert.pem",
                self.rootpath / "private-key.pem",
            )

            self.cs_cert_pem = cross_signing.cert_pem

            log_assert(
                cross_signing.public_key_pem == self.domain_signing.public_key_pem,
                "Cross-Signing Cert Public Key == Domain Cert Public Key",
            )

    def set_next_update_time(self, cert):
        next_update = cert.not_valid_before + CERT_DURATION
        log_message(
            "Certificate will be used from {0} to {1}".format(
                cert.not_valid_before, next_update
            )
        )
        next_update = (next_update - datetime.datetime.utcnow()).total_seconds()
        self.next_update = next_update

    def save_key_pair_and_cert(self):
        """Save keypair and cert"""
        log_message("Saving: " + str(self.rootpath / "private-key.pem"))
        with open(self.rootpath / "private-key.pem", "wb") as fh_out:
            fh_out.write(
                crypto.save_private_key(self.domain_signing.private_key, PASSPHRASE)
            )

        log_message("Saving: " + str(self.rootpath / "cert.pem"))
        with open(self.rootpath / "cert.pem", "wt") as fh_out:
            fh_out.write(self.domain_signing.cert_pem)

        if self.cs_cert_pem:
            log_message("Saving: " + str(self.rootpath / "cs-cert.pem"))
            with open(self.rootpath / "cs-cert.pem", "wt") as fh_out:
                fh_out.write(self.cs_cert_pem)

    def update_signing_key_and_cert(self):
        """Run cert creation"""

        self.domain_signing = CertKeyPair().init_new()

        csr = crypto.create_csr(self.domain, self.domain_signing.private_key)
        csr_pem = crypto.get_as_pem(csr)

        log_message("Awaiting new cert for domain: " + self.domain)

        signer = AcmeSigner(self.domain, self.email, self.port, self.staging)

        try:
            self.domain_signing.set_cert(signer.get_acme_cert(csr_pem))

            log_success("Obtained new domain cert for: " + self.domain)
        except Exception as e:
            log_failure("Unable to retrieve cert for: " + self.domain)
            log_failure("Reason: " + repr(e))
            self.domain_signing = None
            return

        if self.csca_signing:
            now = datetime.datetime.utcnow()

            cs_cert = crypto.create_signed_cert(
                csr,
                self.csca_signing.cert,
                self.csca_signing.private_key,
                now,
                now + CERT_DURATION,
            )
            self.cs_cert_pem = crypto.get_as_pem(cs_cert)

        self.save_key_pair_and_cert()
        self.set_next_update_time(self.domain_signing.cert)

    def __call__(self, sign_req):
        signature = crypto.sign(sign_req.hash, self.domain_signing.private_key)

        timestamper = random.choice(self.timestampers)

        time_signature, timestamp = timestamper(signature)

        created_dt = parse_date(sign_req.created)

        if not is_time_range_valid(created_dt, timestamp, STAMP_DURATION):
            msg = "Created timestamp is out of range: Must be between {0} and {1}, but is {2}".format(
                timestamp, timestamp + STAMP_DURATION, created_dt
            )
            raise Exception(msg)

        return SignedHash(
            software="authsigner " + __version__,
            hash=sign_req.hash,
            created=sign_req.created,
            signature=signature,
            timeSignature=time_signature,
            domain=self.domain,
            domainCert=self.domain_signing.cert_pem,
            timestampCert=timestamper.cert_pem,
            crossSignedCert=self.cs_cert_pem,
        )

    async def renew_loop(self):
        log_message(
            "Signer: Renewing domain certificate in {0}".format(
                datetime.timedelta(seconds=self.next_update)
            )
        )
        loop = asyncio.get_event_loop()
        await asyncio.sleep(self.next_update)
        update_time = CERT_DURATION.total_seconds()
        global renewing

        while True:
            log_message("Signer: Running domain certificate update...")
            renewing = True
            await loop.run_in_executor(None, self.update_signing_key_and_cert)
            log_message(
                "Signer: Renew complete, next renew in {0}".format(
                    datetime.timedelta(seconds=update_time)
                )
            )
            renewing = False
            await asyncio.sleep(update_time)
