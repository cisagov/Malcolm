FROM jwilder/nginx-proxy:alpine

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"

ADD nginx/nginx.conf /etc/nginx/nginx.conf
ADD docs/images/icon/favicon.ico /etc/nginx/favicon.ico