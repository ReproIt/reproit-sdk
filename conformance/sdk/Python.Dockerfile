FROM docker.io/library/python:3.14.6-slim-bookworm@sha256:4c92ffcde4dd6f1ff72a24518f49fd4990b27134987dfa31a733badde66df9f8
COPY sdks/python /source/sdks/python
COPY crates/reproit-sdk-engine/sdk-engine-abi.json \
    /source/crates/reproit-sdk-engine/sdk-engine-abi.json
COPY .core/specs/v1/protocol-vectors.json /source/.core/specs/v1/protocol-vectors.json
COPY .core/specs/v1/cloud-api-vectors.json /source/.core/specs/v1/cloud-api-vectors.json
COPY .core/specs/v1/processor-capture.json /source/.core/specs/v1/processor-capture.json
COPY .core/specs/v1/semantic-observation-vector.json \
    /source/.core/specs/v1/semantic-observation-vector.json
RUN python -m pip install --disable-pip-version-check \
    setuptools==83.0.0 uv==0.11.29 /source/sdks/python
ENV REPROIT_CORE_ROOT=/source/.core
ENV REPROIT_PROTOCOL_VECTORS=/source/.core/specs/v1/protocol-vectors.json
ENV REPROIT_CLOUD_API_VECTORS=/source/.core/specs/v1/cloud-api-vectors.json
ENV REPROIT_PROCESSOR_CAPTURE=/source/.core/specs/v1/processor-capture.json
ENV UV_CACHE_DIR=/tmp/uv-cache
ENTRYPOINT ["python", "-m", "unittest", "discover", "-s", "/source/sdks/python/tests"]
