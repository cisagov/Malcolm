FROM debian:13-slim

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

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
      libssl-dev \
      libtool \
      make \
      pkg-config && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD build-htpdate-deb.sh /usr/local/bin/

ENTRYPOINT ["/bin/bash", "/usr/local/bin/build-htpdate-deb.sh"]
