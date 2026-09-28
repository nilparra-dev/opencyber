ARG KALI_BASE=kalilinux/kali-rolling@sha256:d1d7e581ed60b0bbf9cb8a4bc853526355978f3b943d3a1d7dc7ce209e4231b6
FROM ${KALI_BASE}
LABEL org.opencyber.kali.version="1"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dnsutils file git iproute2 jq nmap openssl python3 python3-pip \
    ripgrep sqlmap unzip wget whois && \
    mkdir -p /opt/opencyber /work && \
    dpkg-query -W > /opt/opencyber/packages.txt && \
    chmod 1777 /work && rm -rf /var/lib/apt/lists/*
ENV HOME=/work TMPDIR=/tmp
USER 1000:1000
WORKDIR /work
CMD ["sleep", "infinity"]
