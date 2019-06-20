FROM debian:buster-slim

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"

ARG ES_HOST=elasticsearch
ARG ES_PORT=9200
ARG CURATOR_TIMEOUT=120
ARG CURATOR_MASTER_ONLY=False
ARG CURATOR_LOGLEVEL=INFO
ARG CURATOR_LOGFORMAT=default

ARG CURATOR_CLOSE_UNITS=years
ARG CURATOR_CLOSE_COUNT=5
ARG CURATOR_DELETE_UNITS=years
ARG CURATOR_DELETE_COUNT=99
ARG CURATOR_DELETE_GIGS=1000000

ENV ES_HOST $ES_HOST
ENV ES_PORT $ES_PORT
ENV CURATOR_TIMEOUT $CURATOR_TIMEOUT
ENV CURATOR_MASTER_ONLY $CURATOR_MASTER_ONLY
ENV CURATOR_LOGLEVEL $CURATOR_LOGLEVEL
ENV CURATOR_LOGFORMAT $CURATOR_LOGFORMAT

ENV CURATOR_CLOSE_UNITS $CURATOR_CLOSE_UNITS
ENV CURATOR_CLOSE_COUNT $CURATOR_CLOSE_COUNT
ENV CURATOR_DELETE_UNITS $CURATOR_DELETE_UNITS
ENV CURATOR_DELETE_COUNT $CURATOR_DELETE_COUNT
ENV CURATOR_DELETE_GIGS $CURATOR_DELETE_GIGS

ENV DEBIAN_FRONTEND noninteractive
ENV CURATOR_VERSION "5.7.6"
ENV CRON "0 0 * * *"
ENV CONFIG_FILE "/config/config_file.yml"
ENV ACTION_FILE "/config/action_file.yml"
ENV CURATOR_USER "curator"

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
    apt-get update && \
    apt-get  -y -q install \
      build-essential \
      cron \
      procps \
      psmisc \
      python3 \
      python3-dev \
      python3-pip && \
    pip3 install elasticsearch-curator==${CURATOR_VERSION} && \
    groupadd --gid 1000 ${CURATOR_USER} && \
      useradd -M --uid 1000 --gid 1000 ${CURATOR_USER} && \
    apt-get -q -y --purge remove python3-dev build-essential && \
      apt-get -q -y autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    bash -c 'echo "${CRON} su -c \"/usr/local/bin/curator --config ${CONFIG_FILE} ${ACTION_FILE}\" ${CURATOR_USER} >/proc/1/fd/1 2>/proc/1/fd/2" | crontab -'

ADD curator/scripts /usr/local/bin/
ADD curator/config /config/

CMD ["/usr/local/bin/cron_env_deb.sh"]
