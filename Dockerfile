# ─────────────────────────────────────────────────────────────
#  ARES — Autonomous Recon & Exploitation System
# ─────────────────────────────────────────────────────────────

FROM golang:1.22-bullseye AS go-builder

ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest

# ─────────────────────────────────────────────────────────────

FROM python:3.11-slim

LABEL maintainer="farixzz <https://github.com/farixzz>"
LABEL description="ARES — AI-powered autonomous penetration testing CLI"
LABEL version="2.0.2"

# Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PATH=$PATH:/root/go/bin \
    OLLAMA_HOST=http://host.docker.internal:11434

# Install system security tools + runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    sqlmap \
    hydra \
    whatweb \
    commix \
    curl \
    git \
    wget \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled Go tools from builder stage
COPY --from=go-builder /root/go/bin/nuclei   /usr/local/bin/nuclei
COPY --from=go-builder /root/go/bin/katana   /usr/local/bin/katana
COPY --from=go-builder /root/go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /root/go/bin/ffuf     /usr/local/bin/ffuf

# Update Nuclei templates at build time so first run is fast
RUN nuclei -update-templates -silent || true

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools==82.0.1 && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create output and wordlist directories
RUN mkdir -p ares_results /usr/share/wordlists

# Verify all tools are present
RUN python ares.py tools --check || true

ENTRYPOINT ["python", "ares.py"]
CMD ["--help"]