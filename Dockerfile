# Hive Colony v3.0 — Runtime-only image (pre-built binaries from host)
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libssl-dev ca-certificates openssh-client openssh-server sshpass \
    curl python3 python3-pip \
    iputils-ping dnsutils netcat-openbsd nmap \
    && rm -rf /var/lib/apt/lists/* && \
    pip3 install --no-cache-dir --break-system-packages flask requests

WORKDIR /hive

COPY target/release/c2-server  /hive/bin/
COPY target/release/queen      /hive/bin/
COPY target/release/worker     /hive/bin/
COPY target/release/drone      /hive/bin/
COPY target/release/honeybee   /hive/bin/
COPY target/release/weaver     /hive/bin/
COPY target/release/swarm      /hive/bin/
COPY target/release/beekeeper  /hive/bin/

COPY tests/ /hive/tests/
COPY scripts/ /hive/scripts/

EXPOSE 8080 8444
CMD ["/hive/bin/c2-server", "--port", "8444", "--loot-dir", "/hive/loot", "--db-path", "/hive/c2.db"]
