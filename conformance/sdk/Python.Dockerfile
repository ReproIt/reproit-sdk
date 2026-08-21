FROM docker.io/library/python:3.14.6-slim-bookworm@sha256:4c92ffcde4dd6f1ff72a24518f49fd4990b27134987dfa31a733badde66df9f8
COPY sdks/python /package
RUN python -m pip install --disable-pip-version-check /package && rm -rf /package
COPY sdks/python/tests /tests
COPY .core/specs/v1/protocol-vectors.json /specs/protocol-vectors.json
ENV REPROIT_PROTOCOL_VECTORS=/specs/protocol-vectors.json
COPY .core/specs/v1/cloud-api-vectors.json /specs/cloud-api-vectors.json
ENV REPROIT_CLOUD_API_VECTORS=/specs/cloud-api-vectors.json
COPY .core/specs/v1/processor-capture.json /specs/processor-capture.json
ENV REPROIT_PROCESSOR_CAPTURE=/specs/processor-capture.json
ENTRYPOINT ["python", "-m", "unittest", "discover", "-s", "/tests"]
