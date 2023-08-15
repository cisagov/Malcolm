FROM debian:12-slim

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"

ENV DEBIAN_FRONTEND noninteractive

ENV ARKIME_VERSION "4.4.0"
ENV ARKIME_DIR "/opt/arkime"

RUN sed -i "s/main$/main contrib non-free/g" /etc/apt/sources.list.d/debian.sources && \
  apt-get -q update && \
  apt-get install -q -y --no-install-recommends \
    build-essential \
    curl \
    git-core \
    iproute2 \
    meson \
    ninja-build \
    patch \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    ruby \
    ruby-dev \
    rubygems \
    sudo \
    wget && \
  gem install --no-document fpm && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD arkime_patch/* /opt/patches/
ADD build-arkime-deb.sh /usr/local/bin/
ADD etc /arkime-etc

ENTRYPOINT ["/bin/bash", "/usr/local/bin/build-arkime-deb.sh"]
