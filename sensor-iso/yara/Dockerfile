FROM debian:12-slim

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
      automake \
      bison \
      ca-certificates \
      checkinstall \
      curl \
      flex \
      gcc \
      libjansson-dev \
      libmagic-dev \
      libssl-dev \
      libtool \
      make \
      pkg-config && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD build-yara-deb.sh /usr/local/bin/

ENTRYPOINT ["/bin/bash", "/usr/local/bin/build-yara-deb.sh"]
