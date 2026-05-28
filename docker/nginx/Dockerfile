FROM nginx:alpine

# Install openssl for cert generation
RUN apk add --no-cache openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
