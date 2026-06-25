FROM python:3.13-slim

WORKDIR /app

# Install scanner package from PyPI; pin/override via build args when needed.
ARG ANSEDE_VERSION=ansede-static
RUN pip install --no-cache-dir "${ANSEDE_VERSION}"

ENTRYPOINT ["ansede-static"]
