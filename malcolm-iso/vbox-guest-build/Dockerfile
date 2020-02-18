FROM debian:buster-slim

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm.netsec@gmail.com"

ENV DEBIAN_FRONTEND noninteractive

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
  apt-get -q update && \
  apt-get install -q -y --no-install-recommends \
      curl devscripts build-essential debian-keyring equivs && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD build-vboxguest-deb.sh /usr/local/bin/

ENTRYPOINT ["/bin/bash", "/usr/local/bin/build-vboxguest-deb.sh"]
