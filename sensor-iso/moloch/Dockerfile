FROM debian:buster-slim

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm.netsec@gmail.com"

ENV DEBIAN_FRONTEND noninteractive

ENV MOLOCH_VERSION "2.1.2"
ENV MOLOCHDIR "/opt/moloch"

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
  apt-get -q update && \
  apt-get install -q -y --no-install-recommends \
      curl iproute2 git python python-dev sudo ruby ruby-dev rubygems build-essential && \
  gem install --no-ri --no-rdoc fpm && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD build-moloch-deb.sh /usr/local/bin/

ENTRYPOINT ["/bin/bash", "/usr/local/bin/build-moloch-deb.sh"]
