FROM python:3.12-slim-trixie

RUN pip install odxtools

WORKDIR /data

ENTRYPOINT ["/usr/local/bin/python", "generate.py"]
