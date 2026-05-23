FROM python:3.12-slim

LABEL description="NetGuard v3 — Security Monitoring System"

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .

RUN mkdir -p /data

CMD ["python", "-u", "main.py"]
