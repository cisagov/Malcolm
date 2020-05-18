FROM debian:buster-slim

# Copyright (c) 2018 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm.netsec@gmail.com"

ENV DEBIAN_FRONTEND noninteractive
ENV GOPATH=/go
ENV GOBIN=/go/bin
ENV GOARCH=amd64
ENV PATH="$GOBIN:${PATH}"

RUN apt-get update && apt-get install -y \
      'golang=2:1.11~1' \
      'golang-doc=2:1.11~1' \
      'golang-go=2:1.11~1' \
      'golang-src=2:1.11~1' \
      build-essential \
      python \
      python-pip \
      python-virtualenv \
      virtualenv \
      git \
      curl && \
    rm -rf /var/lib/apt/lists/* && \
    pip install pyyaml cookiecutter && \
    mkdir -p "$GOPATH/bin" && \
    bash -c "curl https://glide.sh/get | bash"

ENV BEATS=metricbeat
ENV BEATS_VERSION=7.7.0

ADD ./build.sh /build.sh
RUN [ "chmod", "+x", "/build.sh" ]
RUN [ "mkdir", "-p", "/go" ]
RUN [ "mkdir", "/build" ]

CMD "/build.sh"
