""" crypto utils"""

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.backends import default_backend

from cryptography import x509
from cryptography.x509.oid import NameOID

import jwt


def create_ecdsa_private_key():
    """ Get ECDSA Key"""
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


def create_csr(domain, private_key):
    """ Create CSR"""
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False
        )
    )

    csr = builder.sign(private_key, hashes.SHA256(), backend=default_backend())
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def load_cert(pem):
    """ Load cert from PEM"""
    return x509.load_pem_x509_certificate(pem, backend=default_backend())


def get_public_key_pem(public_key):
    """ Get PEM for public key"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def save_private_key(private_key, passphrase):
    """ Get PEM of encrypted private key"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def load_private_key(pem, passphrase):
    """ Load private key from PEM"""
    return serialization.load_pem_private_key(
        pem, password=passphrase, backend=default_backend()
    )


def load_public_key(pem):
    """ Load public key from PEM"""
    return serialization.load_pem_public_key(pem, backend=default_backend())


def sign(data, private_key):
    """ Sign with private_key, return base64-encoded DER"""
    data = private_key.sign(data.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(data).decode("ascii")


def verify(data, signature, public_key):
    """ Verify signature (base64-encoded DER) with public key"""
    signature = base64.b64decode(signature)
    try:
        public_key.verify(signature, data.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def create_jwt(data, pem):
    return jwt.encode(data, pem, algorithm="ES256K")


def check_jwt(data, pem):
    return jwt.decode(data, pem, algorithms=["ES256K"])
