FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies including security tools
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    sqlmap \
    hydra \
    whatweb \
    commix \
    wget \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for nuclei, katana, subfinder, ffuf)
RUN wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools && \
    pip install --no-cache-dir -r requirements.txt

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest

# Copy application code
COPY . .

# Create output directory
RUN mkdir -p ares_results

# Wordlist directory
RUN mkdir -p /usr/share/wordlists

ENTRYPOINT ["python", "ares.py"]
CMD ["--help"]
