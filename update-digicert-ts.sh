#!/bin/bash
# Update cert and root from https://knowledge.digicert.com/general-information/rfc3161-compliant-time-stamp-authority-server

# old:
#curl -o ./leaf.pem "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/TSACertificate.cer"


# Get Lead and convert to PEM
curl -o ./leaf.cer "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA256RSA4096TimestampResponder20251.cer"

openssl x509 -inform DER -in ./leaf.cer -out ./leaf.pem -outform PEM

# Get Intermediate
curl -o ./intermediate.pem "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.pem"

# Get Root
# Note: this is actual a PEM not a CER
curl -o ./root.pem "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedRootG4.cer"


# concat all
cat ./leaf.pem ./intermediate.pem ./root.pem > ./authsign/trusted/ts-digicert.pem

