ARG PYTHON_IMAGE=python:3.12.11-slim-bookworm
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/agentsim \
    AGENTSIM_DISPOSABLE_CONTAINER=1

WORKDIR /opt/agentsim
COPY agentsim ./agentsim

USER 65532:65532
EXPOSE 8765

HEALTHCHECK --interval=5s --timeout=2s --retries=10 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=1).read()"]

CMD ["python", "-m", "agentsim.lab.server", "--host", "0.0.0.0", "--port", "8765", "--allow-loopback", "--allow-container-bind"]
