"""
Monkey-patch rfc3161ng to support EC keys (FreeTSA switched from RSA to EC in 2026).
The upstream library only handles RSA keys in check_timestamp(). This patch adds
EC key support by detecting the key type and using the correct verify() signature.
"""

import rfc3161ng
from cryptography.hazmat.primitives.asymmetric import ec, padding

# pylint: disable=too-many-arguments, too-many-positional-arguments, too-many-locals, import-outside-toplevel

# Below code is adapted from https://github.com/SSC-ICT-Innovatie/nl-kat-coordination/blob/main/bytes/bytes/timestamping/rfc3161.py
# Licensed under EUPL 1.2 (https://github.com/SSC-ICT-Innovatie/nl-kat-coordination/blob/main/LICENSE)
# See https://github.com/trbs/rfc3161ng/issues/26#issue-4244967580 for more details


_original_check_timestamp = rfc3161ng.check_timestamp


def _patched_check_timestamp(
    tst: bytes,
    certificate: bytes | None = None,
    data: bytes | None = None,
    digest: bytes | None = None,
    hashname: str | None = None,
    nonce: int | None = None,
) -> bool:
    """Wrapper around rfc3161ng.check_timestamp that supports EC public keys."""
    from cryptography.hazmat.primitives import hashes

    try:
        return _original_check_timestamp(
            tst, certificate, data, digest, hashname, nonce
        )
    except TypeError as e:
        if "positional arguments" not in str(e):
            raise

    # EC key path: re-implement the signature verification with correct EC API.
    # We re-parse the TST to extract the signature and signed data.
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type import univ

    if not isinstance(tst, rfc3161ng.TimeStampToken):
        tst, _ = decoder.decode(tst, asn1Spec=rfc3161ng.TimeStampToken())

    signed_data = tst.content
    certificate = rfc3161ng.api.load_certificate(signed_data, certificate)
    signer_info = signed_data["signerInfos"][0]

    content = bytes(
        decoder.decode(
            bytes(tst.content["contentInfo"]["content"]), asn1Spec=univ.OctetString()
        )[0]
    )

    if len(signer_info["authenticatedAttributes"]):
        signer_digest_algorithm = signer_info["digestAlgorithm"]["algorithm"]
        signer_hash_name = rfc3161ng.api.get_hash_from_oid(signer_digest_algorithm)
        s = univ.SetOf()
        for i, x in enumerate(signer_info["authenticatedAttributes"]):
            s.setComponentByPosition(i, x)
        signed_data_bytes = encoder.encode(s)
    else:
        signer_hash_name = hashname or "sha1"
        signed_data_bytes = content

    signature = bytes(signer_info["encryptedDigest"])
    public_key = certificate.public_key()  # type: ignore[union-attr]
    hash_family = getattr(hashes, signer_hash_name.upper())

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, signed_data_bytes, ec.ECDSA(hash_family()))
    else:
        public_key.verify(
            signature, signed_data_bytes, padding.PKCS1v15(), hash_family()
        )

    return True


def apply_patch():
    """ apply monkey-patch to rfc3161ng """
    rfc3161ng.check_timestamp = _patched_check_timestamp
    rfc3161ng.api.check_timestamp = _patched_check_timestamp
