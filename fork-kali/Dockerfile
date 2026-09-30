ARG KALI_BASE=kalilinux/kali-rolling@sha256:d1d7e581ed60b0bbf9cb8a4bc853526355978f3b943d3a1d7dc7ce209e4231b6
FROM ${KALI_BASE}
LABEL org.opencyber.kali.version="4"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    aapt android-framework-res binutils gcc libc6-dev ca-certificates curl dnsutils file git iproute2 jq libcap2-bin nmap openssl openssh-server python3 python3-pip \
    nftables ripgrep sqlmap unzip wget whois && \
    setcap -r /usr/lib/nmap/nmap && \
    mkdir -p /opt/opencyber /work && \
    dpkg-query -W > /opt/opencyber/packages.txt && \
    chmod 1777 /work && rm -rf /var/lib/apt/lists/*
ENV HOME=/work TMPDIR=/tmp
USER 1000:1000
WORKDIR /work
CMD ["sleep", "infinity"]
