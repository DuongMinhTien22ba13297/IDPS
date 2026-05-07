FROM ubuntu:22.04

# Tránh việc cài đặt bị kẹt ở các prompt yêu cầu tương tác
ENV DEBIAN_FRONTEND=noninteractive

# Cài đặt các công cụ cơ bản và thêm repository của Suricata
RUN apt-get update && \
    apt-get install -y software-properties-common wget curl jq && \
    add-apt-repository ppa:oisf/suricata-stable -y && \
    apt-get update && \
    apt-get install -y suricata && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Cập nhật rule (ET Open ruleset)
RUN suricata-update

# Biến môi trường cho Network Interface, mặc định sẽ được truyền từ docker-compose
ENV IFACE=ens33

# Khởi chạy Suricata lắng nghe trên Interface được chỉ định
CMD ["sh", "-c", "suricata -c /etc/suricata/suricata.yaml -i $IFACE"]
