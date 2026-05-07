#!/bin/bash

# Kiểm tra xem mã nguồn autodefense_daemon.py có tồn tại không
if [ ! -f "/app/src/autodefense_daemon.py" ]; then
  echo "ERROR: /app/src/autodefense_daemon.py not found!"
  echo "Vui lòng mount volume đúng cách: ./src:/app/src"
  # Để debug, không thoát ngay
  tail -f /dev/null
fi

echo "Starting Autodefense Daemon..."
exec python3 /app/src/autodefense_daemon.py
