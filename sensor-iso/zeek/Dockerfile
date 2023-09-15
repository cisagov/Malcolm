FROM debian:12-slim

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
        bison \
        ca-certificates \
        ccache \
        checkinstall \
        cmake \
        curl \
        flex \
        g++ \
        gcc \
        libfl-dev \
        libgoogle-perftools4 \
        libgoogle-perftools-dev \
        libkrb5-3 \
        libkrb5-dev \
        libmaxminddb-dev \
        libpcap-dev \
        libssl-dev \
        libtcmalloc-minimal4 \
        make \
        ninja-build \
        python3 \
        python3-dev \
        python3-git \
        python3-semantic-version \
        sudo \
        swig \
        zlib1g-dev

ADD build-zeek-deb.sh /usr/local/bin/

ENTRYPOINT [ "/bin/bash", "/usr/local/bin/build-zeek-deb.sh" ]