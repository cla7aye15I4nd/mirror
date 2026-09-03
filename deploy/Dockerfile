FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY malware_archive /app/malware_archive
COPY artifact_viewer /app/artifact_viewer

ENTRYPOINT ["python", "-m", "malware_archive"]
