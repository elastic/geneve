# Build from ~/projects/geneve-obvious-tool so both unreleased POC packages are
# available to the image:
# docker build -f geneve.git/geneve_pipes/Dockerfile -t <image> .
FROM python:3.11-slim

WORKDIR /opt/geneve-obvious-tool
COPY pipes-py.git /opt/geneve-obvious-tool/pipes-py
COPY geneve.git /opt/geneve-obvious-tool/geneve

# elastic-pipes-core is intentionally consumed from its unreleased Git source
# until the planned Pipes base image is available.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir /opt/geneve-obvious-tool/pipes-py /opt/geneve-obvious-tool/geneve

WORKDIR /opt/geneve-obvious-tool/geneve
