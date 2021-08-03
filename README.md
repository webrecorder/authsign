# Request Signer Server

This system represts a signing server that can sign an arbitrary hash passed in via `/sign/<hash>`.

The signed response includes data about the signing server to ensure future validation of authenticity.

The response includes: the public key and signature of the hash, domain certificate of signing server (created from same private key as the public key)

## Operation


1. Install with `pip install -r requirements.txt`

2. Copy `config.sample.yaml` to `config.yaml` and fill in the config options, in particular, the `email` and the `domain`

3. Start server by using the `./run.sh` script.


## Cert validation

The system uses the ACME protocol from LetsEncrypt to request a staging or production cert. For this to work, port 80 must be available as a temp server is started on port 80 to obtain the port. The actual signing API should run on a different port.

Port 80 is a priviliged port and requires running this tool as root. Alternatively, a front-end like nginx can be configured to forward from port 80 to the HTTP verification server. For this reason, it is possible to configure the `port` in the `config.yaml` to be other than 80.


## Tests

To run the test suite, run `py.test --domain <your domain> [--check-port 80]`. The tests must be run on a server that can be verified by ACME HTTP verification (via port 80), but auth server can be started on different port if running behind a proxy.

Note: running tests too often may result in rate limiting from Lets Encrypt.

