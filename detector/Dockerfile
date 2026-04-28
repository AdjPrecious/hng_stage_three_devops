FROM python:3.11-slim

# Install iptables and system dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY *.py ./
COPY config.yaml ./

# Create log directory
RUN mkdir -p /var/log/detector /var/log/nginx

# Non-root user for safety (iptables still needs CAP_NET_ADMIN from compose)
RUN useradd -r -s /bin/false detector && \
    chown -R detector:detector /app /var/log/detector
# Note: /var/log/nginx is mounted from host, so we can't chown it here

USER detector

EXPOSE 8888

CMD ["python", "main.py", "--config", "/app/config.yaml"]
