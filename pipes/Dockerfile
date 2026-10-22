# Build from the Geneve repository checkout:
# docker build -f pipes/Dockerfile -t <image> .
FROM python:3.11-slim

WORKDIR /opt/geneve-obvious-tool
COPY . /opt/geneve-obvious-tool/geneve

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir /opt/geneve-obvious-tool/geneve \
    && pip install --no-cache-dir --no-deps \
      "git+https://github.com/elastic/pipes-py.git@geneve-obvious-tool#egg=elastic-pipes"

WORKDIR /opt/geneve-obvious-tool/geneve
