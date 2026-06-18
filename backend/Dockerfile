# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System libraries required by yara-python, python-magic, ssdeep, and the
# Unicorn/Qiling emulation stack.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libmagic1 \
        libfuzzy-dev \
        libssl-dev \
        pkg-config \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements-emulation.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt
# Emulation extras are optional: the engine falls back to static analysis if
# they are unavailable. Install best-effort so the image always builds.
RUN pip install -r requirements-emulation.txt \
    || echo "WARNING: emulation extras not installed; running in static-only mode"

COPY . .

# Run as an unprivileged user. The worker additionally drops capabilities via
# docker-compose security options.
RUN useradd --create-home --uid 10001 apeiron \
    && mkdir -p /data \
    && chown -R apeiron:apeiron /app /data
USER apeiron

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
