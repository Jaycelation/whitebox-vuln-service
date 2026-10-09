FROM python:3.12-slim

ARG TARGETARCH
ARG SEMGREP_VERSION=1.179.0
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.74.0
ARG OSV_SCANNER_VERSION=2.6.0
ARG JOERN_VERSION=4.0.631
ARG INSTALL_JOERN=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    HOME=/data/home \
    XDG_CACHE_HOME=/data/cache \
    PATH=/opt/joern/joern-cli:${PATH}

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/* \
    && case "$TARGETARCH" in \
         amd64) GITLEAKS_ARCH=x64; TRIVY_ARCH=64bit; OSV_ARCH=amd64 ;; \
         arm64) GITLEAKS_ARCH=arm64; TRIVY_ARCH=ARM64; OSV_ARCH=arm64 ;; \
         *) echo "Unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${OSV_ARCH}" -o /usr/local/bin/osv-scanner \
    && chmod 0755 /usr/local/bin/osv-scanner \
    && rm -f /tmp/gitleaks.tar.gz /tmp/trivy.tar.gz

RUN if [ "$INSTALL_JOERN" = "1" ]; then \
      case "$TARGETARCH" in \
        amd64) JOERN_ARCH=x86_64 ;; \
        arm64) JOERN_ARCH=arm64 ;; \
        *) echo "Unsupported Joern architecture: $TARGETARCH" >&2; exit 1 ;; \
      esac; \
      apt-get update \
      && apt-get install -y --no-install-recommends bash openjdk-21-jre-headless unzip \
      && rm -rf /var/lib/apt/lists/* \
      && curl -fsSL "https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-cli-linux-${JOERN_ARCH}.zip" -o /tmp/joern.zip \
      && mkdir -p /opt/joern \
      && unzip -q /tmp/joern.zip -d /opt/joern \
      && rm -f /tmp/joern.zip; \
    fi

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt "semgrep==${SEMGREP_VERSION}"
COPY app.py whitebox_dataflow.py whitebox_evidence.py /app/
COPY web /app/web

RUN groupadd --system scanner \
    && useradd --system --gid scanner --home-dir /data/home --create-home scanner \
    && mkdir -p /data/jobs /data/cache /data/home \
    && chown -R scanner:scanner /data

USER scanner
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
