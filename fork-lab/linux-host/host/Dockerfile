# Linux host laboratory image. The base is pinned by digest; apt packages follow the Debian bookworm
# repository at build time, so a rebuild can install newer patch levels.
ARG DEBIAN_BASE=debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
FROM ${DEBIAN_BASE}
ARG VARIANT=hardened
LABEL org.opencyber.lab.kind="linux-host" org.opencyber.lab.variant="${VARIANT}"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo libcap2-bin && \
    rm -rf /var/lib/apt/lists/*
COPY variants/ /opt/lab/variants/
RUN sh /opt/lab/variants/common.sh && sh "/opt/lab/variants/${VARIANT}.sh" && rm -rf /opt/lab/variants
COPY --chmod=0755 entrypoint.sh /usr/local/bin/lab-entrypoint
ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
