""" crypto utils"""

import base64
import binascii
import traceback

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.backends import default_backend

from cryptography import x509
from cryptography.x509.oid import NameOID

import pem

from authsign.log import debug_error


def create_ecdsa_private_key():
    """Get ECDSA Key"""
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


def create_csr(domain, private_key):
    """Create CSR"""
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False
        )
    )

    return builder.sign(private_key, hashes.SHA256(), backend=default_backend())


def get_as_pem(csr):
    """Convert a csr or cert object to PEM"""
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def create_signed_cert(csr, ca_cert, private_ca_key, start_date, end_date):
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


def load_cert(cert_pem):
    """Load cert from PEM"""
    return x509.load_pem_x509_certificate(cert_pem, backend=default_backend())


def get_cert_subject_name(cert):
    """Get the subject name (domain) from a cert"""
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def get_fingerprint(cert):
    """Get the cert fingerprint as SHA-256 hex string"""
    return binascii.b2a_hex(cert.fingerprint(hashes.SHA256())).decode("ascii")


def get_public_key_pem(public_key):
    """Get PEM for public key"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def save_private_key(private_key, passphrase):
    """Get PEM of encrypted private key"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def load_private_key(pem_data, passphrase):
    """Load private key from PEM"""
    return serialization.load_pem_private_key(
        pem_data, password=passphrase, backend=default_backend()
    )


def load_public_key(pem_data):
    """Load public key from PEM"""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


def sign(data, private_key):
    """Sign with private_key, return base64-encoded DER"""
    data = private_key.sign(data.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(data).decode("ascii")


def verify(data, signature, public_key):
    """Verify signature (base64-encoded DER) with public key"""
    signature = base64.b64decode(signature)
    data = data.encode("ascii")
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        debug_error(traceback.format_exc())
        return False


def validate_cert(cert, public_key):
    """Validation of cert with issuer cert public key (RSA or ECDSA only)
    Does not alone imply the cert is trusted.

    """
    try:
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


def validate_cert_chain(cert_pem):
    """Validate a cert chain stored in PEM file.
    Each cert is validated with key of next cert in PEM file
    Returns all parsed certs, last cert being the root
    """
    prev_cert = None
    certs = []
    for cert in pem.parse(cert_pem):
        cert = load_cert(cert.as_bytes())
        certs.append(cert)
        if prev_cert:
            if not validate_cert(prev_cert, cert.public_key()):
                return None

        prev_cert = cert

    return certs
