FROM python:3.10-slim

# Cài đặt iptables và iproute2 để can thiệp tường lửa và mạng
RUN apt-get update && \
    apt-get install -y iptables iproute2 libpcap-dev gcc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements và cài đặt
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Script khởi chạy
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
