"""crypto utils"""

import base64
import binascii
import traceback
from datetime import datetime

import rfc3161ng

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
    PrivateKeyTypes,
    PublicKeyTypes,
)

from cryptography.hazmat.backends import default_backend

from cryptography import x509
from cryptography.x509.oid import NameOID

from pyasn1.codec.der import encoder

import pem

from authsign.log import debug_error

PublicKey = ec.EllipticCurvePublicKey
PrivateKey = ec.EllipticCurvePrivateKey
Certificate = x509.Certificate
CSR = x509.CertificateSigningRequest


def create_ecdsa_private_key() -> ec.EllipticCurvePrivateKey:
    """Get ECDSA Key"""
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


def create_csr(
    domain: str, private_key: ec.EllipticCurvePrivateKey
) -> x509.CertificateSigningRequest:
    """Create CSR"""
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False
        )
    )

    return builder.sign(private_key, hashes.SHA256(), backend=default_backend())


def get_as_pem(csr_or_cert: x509.CertificateSigningRequest | x509.Certificate) -> bytes:
    """Convert a csr or cert object to PEM"""
    return csr_or_cert.public_bytes(serialization.Encoding.PEM)


def create_signed_cert(
    csr: x509.CertificateSigningRequest,
    ca_cert: x509.Certificate,
    private_ca_key: ec.EllipticCurvePrivateKey,
    start_date: datetime,
    end_date: datetime,
) -> x509.Certificate:
    """Return a signed certificate from a CSR, using a CA cert + private key"""
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start_date)
        .not_valid_after(end_date)
    )

    return builder.sign(private_ca_key, hashes.SHA256())


def load_cert(cert_pem: bytes) -> x509.Certificate:
    """Load cert from PEM"""
    return x509.load_pem_x509_certificate(cert_pem, backend=default_backend())


def get_cert_subject_name(cert: x509.Certificate) -> str:
    """Get the subject name (domain) from a cert, using either CN or SAN Extension"""
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        res = cn_attrs[0].value
        if isinstance(res, bytes):
            res = res.decode("utf-8")
        return res

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        domains = san.value.get_values_for_type(x509.DNSName)
        if domains:
            return domains[0]
    except x509.ExtensionNotFound:
        pass

    return ""


def get_fingerprint(cert: x509.Certificate) -> str:
    """Get the cert fingerprint as SHA-256 hex string"""
    return binascii.b2a_hex(cert.fingerprint(hashes.SHA256())).decode("ascii")


def get_public_key_pem(public_key: CertificatePublicKeyTypes) -> bytes:
    """Get PEM for public key"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def save_private_key(
    private_key: ec.EllipticCurvePrivateKey, passphrase: bytes
) -> bytes:
    """Get PEM of encrypted private key"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def load_private_key(pem_data: bytes, passphrase: bytes) -> PrivateKeyTypes:
    """Load private key from PEM"""
    return serialization.load_pem_private_key(
        pem_data, password=passphrase, backend=default_backend()
    )


def load_public_key(pem_data: bytes) -> PublicKeyTypes:
    """Load public key from PEM"""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


def sign(data: str, private_key: ec.EllipticCurvePrivateKey) -> str:
    """Sign with private_key, return base64-encoded DER"""
    data_bytes = private_key.sign(data.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(data_bytes).decode("ascii")


def verify(data: str, signature: str, public_key: PublicKeyTypes) -> bool:
    """Verify signature (base64-encoded DER) with public key"""
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    sig_bytes = base64.b64decode(signature)
    data_str = data.encode("ascii")
    try:
        public_key.verify(sig_bytes, data_str, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        debug_error(traceback.format_exc())
        return False


def validate_cert(
    cert: x509.Certificate, public_key: CertificatePublicKeyTypes
) -> bool:
    """Validation of cert with issuer cert public key (RSA or ECDSA only)
    Does not alone imply the cert is trusted.

    """
    try:
        assert cert.signature_hash_algorithm
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )

        # only supported RSA and ECDSA certs
        else:
            return False

        return True
    except Exception:
        debug_error(traceback.format_exc())
        return False


def validate_cert_chain(cert_pem: bytes) -> list[x509.Certificate]:
    """Validate a cert chain stored in PEM file.
    Each cert is validated with key of next cert in PEM file
    Returns all parsed certs, last cert being the root
    """
    prev_cert = None
    certs = []
    for pem_entry in pem.parse(cert_pem):
        cert = load_cert(pem_entry.as_bytes())
        certs.append(cert)
        if prev_cert:
            if not validate_cert(prev_cert, cert.public_key()):
                return []

        prev_cert = cert

    return certs


def get_pem_from_tst(tst: rfc3161ng.TimeStampToken) -> str:
    """extract the certs from TST token. Available when RemoteTimestamper created with include_tsa_certificates=true"""
    pem_str = ""
    certs = tst["content"]["certificates"]

    for cert in certs:
        der = encoder.encode(cert)
        cert = x509.load_der_x509_certificate(der)
        pem_str += get_as_pem(cert).decode("ascii")

    return pem_str
