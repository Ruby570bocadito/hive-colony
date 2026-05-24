# Hive Colony v3.0 — Runtime-only image (pre-built binaries from host)
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libssl-dev ca-certificates openssh-client curl python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* && \
    pip3 install --no-cache-dir --break-system-packages flask requests

WORKDIR /hive

COPY target/release/worker    /hive/bin/
COPY target/release/drone     /hive/bin/
COPY target/release/honeybee  /hive/bin/
COPY target/release/weaver    /hive/bin/
COPY target/release/queen     /hive/bin/
COPY target/release/stinger   /hive/bin/
COPY target/release/beekeeper /hive/bin/
COPY target/release/swarm     /hive/bin/
COPY target/release/buzz      /hive/bin/

COPY target/release/libhive_base.rlib   /hive/lib/
COPY target/release/libagent_base.rlib  /hive/lib/

COPY tests/ /hive/tests/
COPY scripts/ /hive/scripts/

EXPOSE 8080 8444
CMD ["python3", "/hive/tests/c2_server.py", "--port", "8444"]
