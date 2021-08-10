# AuthSigner: Signing Server + Verifier

This system provides a signing + verifying server that can sign an arbitrary data passed POSTed to `/sign`, as well as verify the signed response when POSTed to `/verify`.

## Operation

1. Install with `pip install -r requirements.txt`

2. Copy `config.sample.yaml` to `config.yaml` and fill in the config options, in particular, the `email` and the `domain`

3. Start server by using the `./run.sh` script.

### Signing

To support signing, the following data is created in the `./data` directory by default:

- private-key.pem - an ECDSA private key
- cert.pem - the domain certificate (obtained via lets encrypt) created via private-key.pem
- cs-cert.pem - a 'cross-signing' certificate, also created with private-key.pem but with a custom CA.

The key and the cert(s) are rotated every 48 hours.

Signing is done by making a POST request to `/sign` containing the data to sign and the creation date.

The data is POSTed as JSON ojbect: `{"hash": "...", "created": "..."}`

### Auth Token

For additional security, an auth token can be configured in the `config.yaml` or via an `AUTH_TOKEN` environment variable. The auth token
will guard all signing requests, and needs to be passed to the client outside of the app.


### Cross-Signing

The authsigner also supports an optional 'cross-signing' CA, that can generate a certificate signed with the same private key as the domain (Lets Encrypt) certificate,
using a privately created certificate authority. This allows for a backup validation to domain ownership, separate from LE.

To enable this, a `csca-cert` and `csca-private-key` fields should be set in the YAML config, pointing to a Certificate Authority that will be used for cross-signing.
The cross-singing cert chain is then also included in the response.

### Signed Response

The signed response includes a JSON with the following fields:
- `hash`: original data
- `created`: the created date passed in.
- `software`: the tool used to create the signature, would be `authsign <version>` where `<version>` is the current version of this package.
- `signature`: signature of hash with private key from cert
- `domainCert`: PEM-encoded cert chain of the domain certificate (including CA)
- `domain`: the FQDN of the observer domain
- `crossSignedCert`: PEM-encoded cert chain signed with same key as `domainCert` but using the cross-signing CA (optional)
- `timeSignature`: a signature of previous 'signature' using the timestamp via timestamping server
- `timestampCert`: PEM-encoded cert chain of the timestamp certificate (including CA)


Note: By design, the creation date must be close to the current date of the timestamping server. Signing data 'too old' or wrong date will be rejected.

### Verification

The verification API includes POSTing the signed JSON response to the `/verify` endpoint. (No auth token is required to verify).

The verification checks include:
- checking the signature using the public key from domain cert (and optionally, the cross-signing cert)
- checking the timeSignature is valid for the timestamp using the timestampCert
- checking that the signed created timestamp is within ten minutes of claimed signing time, and the domain cert was issued within 48-hours of signing time.
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

