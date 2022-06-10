import json
import authsign.main

on_starting = authsign.main.load_certs

on_exit = authsign.main.on_exit

preload_app = True

with open("log.json") as fh:
    logconfig_dict = json.loads(fh.read())
