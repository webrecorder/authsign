#!/bin/sh
# can configure token here
#export AUTH_TOKEN=token
uvicorn authsign.main:app --port 8080 --host 0.0.0.0 --log-config log.json
