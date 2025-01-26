#!/bin/sh

envsubst < /usr/share/nginx/html/well-known.json.template > /usr/share/nginx/html/well-known.json
nginx -g 'daemon off;'