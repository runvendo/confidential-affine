# Rootless Postgres (pgvector) + WAL-G, for Tinfoil confidential enclaves.
# - Runs as the `postgres` user (no setuid; Tinfoil drops all caps).
# - WAL-G ships base backups + WAL to R2, client-side encrypted (libsodium).
# - Restore-on-boot: if the data dir is empty and a backup exists in R2, fetch it.
FROM pgvector/pgvector:pg16

USER root
ARG WALG_VERSION=v3.0.5
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates wget; \
    wget -qO /tmp/walg.tar.gz "https://github.com/wal-g/wal-g/releases/download/${WALG_VERSION}/wal-g-pg-ubuntu-22.04-amd64.tar.gz"; \
    tar -xzf /tmp/walg.tar.gz -C /usr/local/bin; \
    mv /usr/local/bin/wal-g-pg-ubuntu-22.04-amd64 /usr/local/bin/wal-g; \
    chmod 0755 /usr/local/bin/wal-g; \
    rm -f /tmp/walg.tar.gz; \
    apt-get purge -y wget; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*

COPY entrypoint-walg.sh /usr/local/bin/entrypoint-walg.sh
RUN chmod 0755 /usr/local/bin/entrypoint-walg.sh

USER postgres
ENTRYPOINT ["/usr/local/bin/entrypoint-walg.sh"]
CMD ["postgres"]
