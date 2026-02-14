FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir .

ENV DECOY_BIND=0.0.0.0
ENV DECOY_HTTP_PORT=8080
ENV DECOY_SSH_PORT=2222
ENV DECOY_DB=/data/decoy.db

RUN mkdir -p /data

EXPOSE 8080 2222

CMD ["decoy", "serve"]
