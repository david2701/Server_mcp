# ssh-vault: app autoalojada (panel + MCP remoto + proxy de LLMs)
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 vault \
 && mkdir -p /data && chown vault:vault /data && chmod 700 /data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY ssh_vault ./ssh_vault
RUN pip install --no-cache-dir . && rm -rf /app/build

USER vault
ENV SSH_VAULT_HOME=/data \
    VAULT_AUDIT_LOG=/data/audit.log \
    PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8787

# La URL pública llega por VAULT_PUBLIC_URL (ver docker-compose.yml).
CMD ["vault", "serve", "--host", "0.0.0.0", "--port", "8787", "--behind-proxy"]
