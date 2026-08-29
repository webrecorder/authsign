"""
Generate or load certs and handle signing
"""

from pathlib import Path

import datetime
import base64
import random
import asyncio
import traceback
from typing import Self

from pyasn1.codec.der import encoder

import rfc3161ng

from authsign.patch_rfc3161ng import apply_patch

from authsign import crypto, __version__

from authsign.acme_signer import AcmeSigner

from authsign.model import SignedHash, SignReq
from authsign.utils import (
    CERT_DURATION,
    STAMP_DURATION,
    YEARS,
    no_older_then,
)

from authsign.log import log_assert, log_message, log_failure, log_success

PASSPHRASE = b"passphrase"

renewing = False

# patch rfc3161ng to be able to handle EC keys
apply_patch()


# ============================================================================
# pylint: disable=too-few-public-methods
class Timestamper:
    """handle rfc3161 timestamp signing"""

    _timestamper: rfc3161ng.RemoteTimestamper

    def __init__(self, url: str, **_kwargs):
        # passing include_tsa_certificate=True ensures the server returns the
        # cert chain, instead of passing one in.
        # certificate=b"" is necessary to avoid exception due to empty cert, see:
        # https://codeberg.org/elbosso/rfc3161timestampingserver#python-client
        self._timestamper = rfc3161ng.RemoteTimestamper(
            url, certificate=b"", hashname="sha256", include_tsa_certificate=True
        )

    def __call__(self, signature: str) -> tuple[bytes, datetime.datetime, str]:
        """perform signing op"""
        tsr = self._timestamper(data=signature.encode("ascii"), return_tsr=True)

        tst = tsr.time_stamp_token

        result = encoder.encode(tsr)

        pem = crypto.get_pem_from_tst(tst)

        return base64.b64encode(result), rfc3161ng.get_timestamp(tst, naive=False), pem


# ============================================================================
# pylint: disable=too-many-instance-attributes,too-many-arguments,too-many-positional-arguments
class CertKeyPair:
    """Loads a cert + private key from PEM, extracts public key from cert"""

    private_key: crypto.ECPrivateKey
    public_key: crypto.ECPublicKey

    public_key_pem: bytes

    cert_pem: bytes
    cert: crypto.Certificate

    def __init__(
        self,
        private_key: crypto.ECPrivateKey,
        public_key: crypto.ECPublicKey,
        public_key_pem: bytes,
        cert_pem: bytes,
        cert: crypto.Certificate,
    ):
        self.private_key = private_key
        self.public_key = public_key

        self.public_key_pem = public_key_pem

        self.cert_pem = cert_pem
        self.cert = cert

    @classmethod
    def load(
        cls,
        name: Path | str,
        certfile: Path | str,
        private_key_filename: Path | str,
        passphrase=PASSPHRASE,
        duration=CERT_DURATION,
    ) -> Self:
        """load existing keypair and certs from file system. load public key from cert"""

        log_message("{0}: Loading Cert: {1}".format(name, str(certfile)))
        with open(certfile, "rb") as fh_in:
            cert_pem = fh_in.read()
            cert = crypto.load_cert(cert_pem)

        public_key = cert.public_key()
        assert isinstance(
            public_key, crypto.ECPublicKey
        ), "Only EC public key supported"
        public_key_pem = crypto.get_public_key_pem(public_key)

        log_message(
            "{0}: Loading Private Key: {1}".format(name, str(private_key_filename))
        )
        with open(private_key_filename, "rb") as fh_in:
            data = fh_in.read()
            private_key = crypto.load_private_key(data, passphrase)
            assert isinstance(
                private_key, crypto.ECPrivateKey
            ), "Only EC private keys supported"

        key_pair = cls(private_key, public_key, public_key_pem, cert_pem, cert)

        key_pair.test_keys(duration)

        return key_pair

    @classmethod
    def init_new(cls, domain: str, signer: AcmeSigner) -> tuple[Self, crypto.CSR]:
        """init new key pair for signing"""
        private_key = crypto.create_ecdsa_private_key()
        public_key = private_key.public_key()
        public_key_pem = crypto.get_public_key_pem(public_key)

        csr = crypto.create_csr(domain, private_key)
        csr_pem = crypto.get_as_pem(csr)

        cert_pem = signer.get_acme_cert(csr_pem)
        cert = crypto.load_cert(cert_pem)

        return cls(private_key, public_key, public_key_pem, cert_pem, cert), csr

    def test_keys(
        self, duration: datetime.timedelta, data="Data Signature Test"
    ) -> None:
        """Test key pair sign/verify to ensure its valid"""
        signature = crypto.sign(data, self.private_key)

        log_assert(
            crypto.verify(data, signature, self.public_key), "Validating key pair"
        )

        now = datetime.datetime.now(datetime.UTC)

        log_assert(
            self.cert.not_valid_before_utc
            <= now
            <= self.cert.not_valid_before_utc + duration
            and now <= self.cert.not_valid_after_utc,
            "Validating cert still valid",
        )


# ============================================================================
# pylint: disable=too-many-arguments
class Signer:
    """Signing cert, private, public key generator"""

    domain: str
    email: str
    port: int
    staging: bool

    rootpath: Path

    timestampers: list[Timestamper] = []

    auth_token: str | None

    domain_signing: CertKeyPair

    csca_signing: CertKeyPair | None = None
    cs_cert_pem: bytes | None = None

    cert_duration: datetime.timedelta
    stamp_duration: datetime.timedelta

    next_update: float = 0

    def __init__(
        self,
        domain: str,
        email: str,
        port: int,
        staging: bool = True,
        output: str | None = None,
        timestamping=None,
        auth_token: str | None = None,
        csca_cert: str | None = None,
        csca_private_key: str | None = None,
        cert_duration: datetime.timedelta | None = None,
        stamp_duration: datetime.timedelta | None = None,
    ):
        self.domain = domain
        self.email = email
        self.port = port
        self.staging = staging

        self.auth_token = auth_token

        if self.auth_token:
            log_message("Auth Token Enabled")
        else:
            log_message("Auth Token Not Enabled")

        self.rootpath = Path(output or "./data")
        self.rootpath.mkdir(exist_ok=True)

        self.cert_duration = cert_duration or CERT_DURATION
        self.stamp_duration = stamp_duration or STAMP_DURATION

        if csca_cert and csca_private_key:
            self.csca_signing = CertKeyPair.load(
                "Cross-Signing",
                csca_cert,
                csca_private_key,
                passphrase=None,
                duration=YEARS,
            )
        else:
            self.csca_signing = None

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

        self.timestampers = [Timestamper(**ts_data) for ts_data in timestamping]

    def validate_token(self, auth_header):
        """validate the passed in auth header token"""
        if not self.auth_token:
            return True

        if not auth_header or not auth_header.startswith("bearer "):
            return False

        return auth_header.split(" ")[1] == self.auth_token

    def load_key_pair_and_cert(self) -> None:
        """Load key pair and cert"""

        self.domain_signing = CertKeyPair.load(
            "Domain Auth",
            self.rootpath / "cert.pem",
            self.rootpath / "private-key.pem",
            duration=self.cert_duration,
        )

        if self.csca_signing:
            cross_signing = CertKeyPair.load(
                "Cross-Signing Cert",
                self.rootpath / "cs-cert.pem",
                self.rootpath / "private-key.pem",
                duration=self.cert_duration,
            )

            self.cs_cert_pem = cross_signing.cert_pem

            log_assert(
                cross_signing.public_key_pem == self.domain_signing.public_key_pem,
                "Cross-Signing Cert Public Key == Domain Cert Public Key",
            )

    def set_next_update_time(self, cert: crypto.Certificate) -> None:
        """store the time for next cert renew"""
        next_update_dt = cert.not_valid_before_utc + self.cert_duration
        log_message(
            "Certificate will be used from {0} to {1}".format(
                cert.not_valid_before_utc, next_update_dt
            )
        )
        next_update = (
            next_update_dt - datetime.datetime.now(datetime.UTC)
        ).total_seconds()
        self.next_update = next_update

    def save_key_pair_and_cert(self) -> None:
        """Save keypair and cert"""

        log_message("Saving: " + str(self.rootpath / "private-key.pem"))
        with open(self.rootpath / "private-key.pem", "wb") as fh_out:
            fh_out.write(
                crypto.save_private_key(self.domain_signing.private_key, PASSPHRASE)
            )

        log_message("Saving: " + str(self.rootpath / "cert.pem"))
        with open(self.rootpath / "cert.pem", "wb") as fh_out:
            fh_out.write(self.domain_signing.cert_pem)

        if self.cs_cert_pem:
            log_message("Saving: " + str(self.rootpath / "cs-cert.pem"))
            with open(self.rootpath / "cs-cert.pem", "wb") as fh_out:
                fh_out.write(self.cs_cert_pem)

    def update_signing_key_and_cert(self) -> None:
        """Run cert creation"""

        signer = AcmeSigner(self.domain, self.email, self.port, self.staging)

        log_message("Awaiting new cert for domain: " + self.domain)

        log_message(f"Staging?: {self.staging}")

        csr: crypto.CSR | None = None

        try:
            self.domain_signing, csr = CertKeyPair.init_new(self.domain, signer)

            log_success("Obtained new domain cert for: " + self.domain)
        except Exception as e:
            log_failure("Unable to retrieve cert for: " + self.domain)
            log_failure("Reason: " + repr(e))
            log_failure(traceback.format_exc())
            raise e

        if self.csca_signing:
            now = datetime.datetime.now(datetime.UTC)

            cs_cert = crypto.create_signed_cert(
                csr,
                self.csca_signing.cert,
                self.csca_signing.private_key,
                now,
                now + self.cert_duration,
            )
            self.cs_cert_pem = crypto.get_as_pem(cs_cert)

        self.save_key_pair_and_cert()
        self.set_next_update_time(self.domain_signing.cert)

    def __call__(self, sign_req: SignReq) -> SignedHash:
        if not self.domain_signing:
            # pylint: disable=broad-exception-raised
            raise Exception("Could not load domain signing cert + keys")

        signature = crypto.sign(sign_req.hash, self.domain_signing.private_key)

        timestamper = random.choice(self.timestampers)

        time_signature, timestamp, ts_pem = timestamper(signature)

        # truncate microseconds, as timestamp server rounds down to closest second
        created = sign_req.created.replace(microsecond=0)

        if not no_older_then(created, timestamp, self.stamp_duration):
            msg = "Created timestamp is out of range: Must be between between {0} and {1}, but is {2}".format(
                timestamp - self.stamp_duration, timestamp, created
            )
            print(msg)
            # pylint: disable=broad-exception-raised
            raise Exception(msg)

        return SignedHash(
            software="authsigner " + __version__,
            hash=sign_req.hash,
            created=sign_req.created,
            signature=signature,
            timeSignature=time_signature,
            domain=self.domain,
            domainCert=self.domain_signing.cert_pem,
            timestampCert=ts_pem,
            crossSignedCert=self.cs_cert_pem,
        )

    async def renew_loop(self) -> None:
        """sleep and run cert renew process in a loop"""
        if not self.domain_signing or not self.domain_signing.cert:
            # pylint: disable=broad-exception-raised
            raise Exception("Could not load domain signing cert + keys")

        self.set_next_update_time(self.domain_signing.cert)

        log_message(
            "Signer: Renewing domain certificate in {0}".format(
                datetime.timedelta(seconds=self.next_update)
            )
        )
        loop = asyncio.get_event_loop()
        await asyncio.sleep(self.next_update)
        update_time = self.cert_duration.total_seconds()
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
