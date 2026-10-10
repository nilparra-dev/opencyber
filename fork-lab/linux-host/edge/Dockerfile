# Publishes the two lab hosts on loopback only. Its output is limited to the hosts' SSH ports.
ARG DEBIAN_BASE=debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
FROM ${DEBIAN_BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends socat iptables && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/lab-edge
ENTRYPOINT ["/usr/local/bin/lab-edge"]
