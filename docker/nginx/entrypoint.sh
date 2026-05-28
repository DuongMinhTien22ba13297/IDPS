#!/bin/sh

# Generate self-signed certs if they don't exist
if [ ! -f /etc/nginx/certs/cert.pem ]; then
    echo "Generating self-signed certificate..."
    mkdir -p /etc/nginx/certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/certs/key.pem \
        -out /etc/nginx/certs/cert.pem \
        -subj "/C=VN/ST=HCM/L=HCM/O=IDPS/OU=Dev/CN=localhost"
fi

# Start Nginx
echo "Starting Nginx..."
exec nginx -g "daemon off;"
