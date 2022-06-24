FROM debian:11-slim

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
      autoconf \
      autoconf-archive \
      automake \
      autotools-dev \
      binutils \
      bison \
      build-essential \
      ca-certificates \
      checkinstall \
      flex \
      git \
      libmhash-dev \
      libpcre2-dev \
      libtool \
      m4 \
      make \
      pkg-config \
      zlib1g-dev && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD build-aide-deb.sh /usr/local/bin/

ENTRYPOINT ["/bin/bash", "/usr/local/bin/build-aide-deb.sh"]
