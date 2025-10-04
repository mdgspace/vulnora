FROM python:3.12-slim

WORKDIR /app  

COPY requirements.txt .
COPY flask-server/ .

ARG SQLMAP_TAG=1.9.5

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    tar \
    gzip \
    whois \
    geoip-bin \
    dnsutils \
    mtr \
    nmap \
    sslscan \
    iputils-ping \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

RUN git clone --depth 1 --branch ${SQLMAP_TAG} https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
 && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
 && chmod +x /usr/local/bin/sqlmap

RUN curl -sL "https://github.com/OWASP/Amass/releases/latest/download/amass_linux_amd64.tar.gz" -o /tmp/amass.tar.gz \
 && tar -xzf /tmp/amass.tar.gz -C /tmp/ \
 && mv /tmp/amass_linux_amd64/amass /usr/local/bin/amass \
 && chmod +x /usr/local/bin/amass \
 && rm -rf /tmp/amass.tar.gz /tmp/amass_linux_amd64

EXPOSE 5001

CMD ["python", "run.py"]
