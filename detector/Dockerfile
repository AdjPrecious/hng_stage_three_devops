FROM python:3.11-slim

# Install iptables and system dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY *.py ./
COPY config.yaml ./

# Create log directories
RUN mkdir -p /var/log/detector /var/log/nginx

# Run as root so iptables works
USER root

EXPOSE 8888

CMD ["python", "main.py", "--config", "/app/config.yaml"]