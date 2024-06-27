#!/bin/bash
# Update cert and root from https://knowledge.digicert.com/general-information/rfc3161-compliant-time-stamp-authority-server

curl "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/TSACertificate.cer" > ./authsign/trusted/ts-digicert.pem
