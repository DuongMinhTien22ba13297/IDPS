FROM python:3.10-slim

# Cài đặt system dependencies:
#   - iptables, iproute2: can thiệp tường lửa và mạng
#   - libpcap-dev: nfstream packet capture
#   - build-essential, gcc, libffi-dev, python3-dev: nfstream CFFI engine build
#   - autoconf, libtool, automake, pkg-config: nfstream native build scripts
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iptables iproute2 libpcap-dev \
        build-essential gcc libffi-dev python3-dev \
        autoconf libtool automake pkg-config && \
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
