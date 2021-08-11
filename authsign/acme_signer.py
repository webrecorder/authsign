"""
Use ACME protocol to obtain a cert!
"""

from contextlib import contextmanager

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import josepy as jose

from acme import challenges
from acme import client
from acme import messages
from acme import standalone


USER_AGENT = "acme-signer"

ACME_STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
ACME_PROD_URL = "https://acme-v02.api.letsencrypt.org/directory"


class AcmeSigner:
    """Acme Signer"""

    def __init__(self, csr_pem, email, port, staging=True):
        self.csr_pem = csr_pem
        self.email = email
        self.port = port

        if isinstance(staging, str):
            self.directory_url = staging
        else:
            self.directory_url = ACME_STAGING_URL if staging else ACME_PROD_URL

        self.user_agent = USER_AGENT
        self.staging = bool(staging)

    def create_rsa_key(self):
        """Create RSA Key for ACME auth request"""
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def get_acme_cert(self, csr_pem):
        """Get a signed cert via ACME"""
        # Register account and accept TOS
        acc_key = jose.jwk.JWKRSA(key=self.create_rsa_key())

        net = client.ClientNetwork(
            acc_key, user_agent=self.user_agent, verify_ssl=not self.staging
        )
        directory = messages.Directory.from_json(net.get(self.directory_url).json())
        client_acme = client.ClientV2(directory, net=net)

        # Terms of Service URL is in client_acme.directory.meta.terms_of_service
        # Creates account with contact information.
        client_acme.new_account(
            messages.NewRegistration.from_data(
                email=self.email, terms_of_service_agreed=True
            )
        )

        orderr = client_acme.new_order(csr_pem)

        # Select HTTP-01 within offered challenges by the CA server
        challb = self.select_http01_chall(orderr)

        # The certificate is ready to be used in the variable "fullchain_pem".
        result = self.perform_http01(client_acme, challb, orderr)
        return result.fullchain_pem

    def select_http01_chall(self, orderr):
        """Extract authorization resource from within order resource."""
        # Authorization Resource: authz.
        # This object holds the offered challenges by the server and their status.
        authz_list = orderr.authorizations

        for authz in authz_list:
            # Choosing challenge.
            # authz.body.challenges is a set of ChallengeBody objects.
            for i in authz.body.challenges:
                # Find the supported challenge.
                if isinstance(i.chall, challenges.HTTP01):
                    return i

        raise Exception("HTTP-01 challenge was not offered by the CA server.")

    @contextmanager
    def challenge_server(self, http_01_resources):
        """Manage standalone server set up and shutdown."""

        servers = None
        try:
            servers = standalone.HTTP01DualNetworkedServers(
                ("", self.port), http_01_resources
            )
            # Start client standalone web server.
            servers.serve_forever()
            yield servers
        finally:
            # Shutdown client web server and unbind from PORT
            servers.shutdown_and_server_close()

    def perform_http01(self, client_acme, challb, orderr):
        """Set up standalone webserver and perform HTTP-01 challenge."""

        response, validation = challb.response_and_validation(client_acme.net.key)

        resource = standalone.HTTP01RequestHandler.HTTP01Resource(
            chall=challb.chall, response=response, validation=validation
        )

        with self.challenge_server({resource}):
            # Let the CA server know that we are ready for the challenge.
            client_acme.answer_challenge(challb, response)

            # Wait for challenge status and then issue a certificate.
            # It is possible to set a deadline time.
            finalized_orderr = client_acme.poll_and_finalize(orderr)

        return finalized_orderr
