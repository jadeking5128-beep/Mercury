FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MERCURY_DB=/data/mercury.db

RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN python -m pip install --no-cache-dir ".[api]"

RUN useradd --create-home --uid 10001 mercury && mkdir -p /data \
    && chown -R mercury:mercury /app /data
USER mercury

EXPOSE 8765
CMD ["uvicorn", "mercury.api:app", "--host", "0.0.0.0", "--port", "8765"]
