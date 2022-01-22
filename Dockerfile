FROM python:3.9

WORKDIR /app

ADD requirements.txt /app

ADD setup.py /app
ADD authsign /app/authsign

ADD README.md /app
ADD log.json /app

RUN python setup.py install

# override by using custom config.yaml, or setting the DOMAIN_OVERRIDE and EMAIL_OVERRIDE
ADD config.sample.yaml config.yaml

CMD uvicorn authsign.main:app --port 8080 --host 0.0.0.0 --log-config /app/log.json

