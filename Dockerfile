FROM python:3.12-slim

WORKDIR /app

ADD requirements.txt /app

ADD setup.py /app
ADD authsign /app/authsign

ADD README.md /app
ADD log.json /app

RUN pip install setuptools

RUN python setup.py install

# override by using custom config.yaml, or setting the DOMAIN_OVERRIDE and EMAIL_OVERRIDE
ADD config.sample.yaml config.yaml

CMD uvicorn authsign.main:app --port 8080 --workers 1 --host 0.0.0.0 --log-config /app/log.json

