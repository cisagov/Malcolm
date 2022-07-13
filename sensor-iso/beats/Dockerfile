FROM debian:buster-slim

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"

ENV DEBIAN_FRONTEND noninteractive
ENV GOPATH=/go
ENV GOBIN=/go/bin
ENV GOARCH=amd64
ENV GOVERS="2:1.15~1~bpo10+1"
ENV PATH="$GOBIN:${PATH}"
ENV PYTHON_EXE=python3

RUN set -x && \
    sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
      echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list && \
      apt-get -q update && \
      apt-get install -y curl git vim-tiny && \
      apt-get install -t buster-backports -y \
        "golang-doc=$GOVERS" \
        "golang-go=$GOVERS" \
        "golang-src=$GOVERS" \
        "golang=$GOVERS" \
        build-essential \
        python3 \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-virtualenv \
        python3-wheel \
        virtualenv && \
    rm -rf /var/lib/apt/lists/* && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 2 && \
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 2 && \
    python3 -m pip install -U pyyaml cookiecutter && \
    mkdir -p "$GOPATH/bin" && \
    bash -c "curl -sSL https://raw.githubusercontent.com/Masterminds/glide.sh/master/get | sed 's@https://glide.sh/@https://raw.githubusercontent.com/Masterminds/glide.sh/master/@g'| bash" && \
    go get -u -d github.com/magefile/mage && \
    cd $GOPATH/src/github.com/magefile/mage && \
    go run bootstrap.go

ENV BEATS=filebeat
ENV BEATS_VERSION=7.10.2

ADD ./build.sh /build.sh
RUN [ "chmod", "+x", "/build.sh" ]
RUN [ "mkdir", "-p", "/go" ]
RUN [ "mkdir", "/build" ]

CMD "/build.sh"
