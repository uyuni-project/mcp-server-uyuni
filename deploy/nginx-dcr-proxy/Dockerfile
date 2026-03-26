FROM nginx:1.27-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx-module-njs \
    && rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx/nginx.conf
COPY dcr_sanitize.js /etc/nginx/njs/dcr_sanitize.js
