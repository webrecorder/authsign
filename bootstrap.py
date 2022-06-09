import json
import authsign.main

on_starting = authsign.main.load_certs

with open("log.json") as fh:
    logconfig_dict = json.loads(fh.read())
