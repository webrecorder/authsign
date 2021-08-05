# AuthSigner: Signing Server + Verifier

This system provides a signing + verifying server that can sign an arbitrary data passed in via `/sign/<data>`, as well as verify the request POST to `/verify`.

## Operation

1. Install with `pip install -r requirements.txt`

2. Copy `config.sample.yaml` to `config.yaml` and fill in the config options, in particular, the `email` and the `domain`

3. Start server by using the `./run.sh` script.

### Signing

To support signing, the following data is created in the `./data` directory by default:

- private-key.pem - an ECDSA private key
- cert.pem - the domain certificate (obtained via lets encrypt)
- auth-token.txt - an auth token for use with the sign endpoint
- long-private-key.pem - A 'long term' private key
- long-public-key.pem - A 'long term' public key

The `private-key.pem` and `cert.pem` are rotated (after 48 hours), while the long term key and auth token are not.

Signing is done by making a POST request to `/sign/<data>` with JWT token stored in auth-token.txt

(The auth token is be passed to client outside of this app for additional security).

The signed response includes a JSON with the following fields:
- hash: original data
- date: date of signing
- signature: signature of hash with private key from cert
- domainCert: PEM-encoded cert chain of the domain certificate (including CA)
- timeSignature: a signature of previous 'signature' using the timestamp via timestamping server
- timestampCert: PEM-encoded cert chain of the timestamp certificate (including CA)
- longPublicKey: the long-term public key
- longSignature: a signature of previous 'signature' with long-term key


### Verification

The verification API includes POSTing the signed JSON response to the `/verify` endpoint. (No auth token is required to verify).

The verification checks include:
- checking the signature and longSignature using the public key from domain cert and longPublicKey
- checking the timeSignature is valid for the timestamp using the timestampCert
- checking that the signed timestamp is within one hour of claimed signing time
- checking that PEM cert chains for domain cert and timestamp cert are valid
- checking that the fingerprints of the root domain cert and timestamp cert are trusted.

### Trusted Roots

To indicate the trusted domain and timestamp certs, the `authsigner/trusted/roots.yaml` file includes the fingerprints (sha-256 hashes) of valid roots.
Currently, this includes the Lets Encrypt CA root and the root for the timestamping server (freetsa.org)

Additional trusted roots can be added as needed. A different trusted roots yaml can be specified in the YAML config as well (see config.sample.yaml for more info)


## Certificate Generation

The system uses the ACME protocol from LetsEncrypt to request a staging or production cert. For this to work, port 80 must be available as a temp server is started on port 80 to obtain the port. The actual signing API should run on a different port.

Port 80 is a priviliged port and requires running this tool as root. Alternatively, a front-end like nginx can be configured to forward from port 80 to the HTTP verification server. For this reason, it is possible to configure the `port` in the `config.yaml` to be other than 80.


## Tests

To run the test suite, run `py.test --domain <your domain> [--check-port 80]`. The tests must be run on a server that can be verified by ACME HTTP verification (via port 80), but auth server can be started on different port if running behind a proxy.

Note: running tests too often may result in rate limiting from Lets Encrypt. The tests use the Lets Encrypt staging servers to generate the certs and trust the staging certificate roots in a custom trust file for verification.

