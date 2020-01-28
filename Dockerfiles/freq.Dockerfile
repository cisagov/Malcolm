FROM debian:buster-slim

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/freq'
LABEL org.opencontainers.image.description='Malcolm container providing an interface to Mark Baggett''s freq_server.py'

ARG FREQ_USER=freq
ARG FREQ_PORT=10004
ARG FREQ_ENABLED=true

ENV FREQ_USER    $FREQ_USER
ENV FREQ_PORT    $FREQ_PORT
ENV FREQ_ENABLED $FREQ_ENABLED

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
    apt-get update && \
    apt-get  -y -q install \
      build-essential \
      curl \
      git \
      procps \
      psmisc \
      python3 \
      python3-dev \
      python3-pip && \
    pip3 install supervisor && \
      mkdir -p /var/log/supervisor && \
    git clone --depth=1 --single-branch -b master https://github.com/markbaggett/freq /opt/freq_server && \
      rm -rf /opt/freq_server/systemd /opt/freq_server/upstart /opt/freq_server/*.md /opt/freq_server/*.exe && \
      mv -v "$(ls /opt/freq_server/*.freq | tail -n 1)" /opt/freq_server/freq_table.freq && \
    groupadd --gid 1000 $FREQ_USER && \
      useradd -M --uid 1000 --gid 1000 --home /nonexistant $FREQ_USER && \
      chown -R $FREQ_USER:$FREQ_USER /opt/freq_server && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove git python3-dev build-essential && \
      apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD freq-server/supervisord.conf /etc/supervisord.conf

WORKDIR /opt/freq_server

EXPOSE $FREQ_PORT

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
