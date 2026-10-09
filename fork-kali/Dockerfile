ARG KALI_BASE=kalilinux/kali-rolling@sha256:d1d7e581ed60b0bbf9cb8a4bc853526355978f3b943d3a1d7dc7ce209e4231b6
FROM ${KALI_BASE}
LABEL org.opencyber.kali.version="6"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    aapt android-framework-res binutils binwalk gcc libc6-dev ca-certificates curl dnsutils file git iproute2 jq libcap2-bin nmap openssl openssh-server python3 python3-pefile python3-pip python3-venv \
    nftables nodejs ripgrep sqlmap unzip wget whois && \
    setcap -r /usr/lib/nmap/nmap && \
    mkdir -p /opt/opencyber /work && \
    dpkg-query -W > /opt/opencyber/packages.txt && \
    chmod 1777 /work && rm -rf /var/lib/apt/lists/*
# Pinned analyzers. Their rules and policies ship inside the packages, so no job needs the network to run them.
RUN python3 -m venv /opt/opencyber/venv && \
    /opt/opencyber/venv/bin/pip install --no-cache-dir checkov==3.3.26 semgrep==1.178.0 && \
    /opt/opencyber/venv/bin/pip freeze > /opt/opencyber/pip-freeze.txt
# Curated offline Semgrep rules. Validated at build time, so a broken rule fails the image instead of a job.
COPY rules/semgrep /opt/opencyber/rules/semgrep
RUN SEMGREP_SEND_METRICS=off /opt/opencyber/venv/bin/semgrep --validate --metrics=off --config /opt/opencyber/rules/semgrep
ENV HOME=/work TMPDIR=/tmp
USER 1000:1000
WORKDIR /work
CMD ["sleep", "infinity"]
