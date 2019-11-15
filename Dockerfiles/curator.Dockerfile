FROM debian:buster-slim

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"
LABEL org.opencontainers.image.authors='Seth.Grover@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/elastalert'
LABEL org.opencontainers.image.description='Malcolm container providing curation for Elasticsearch indices'

ARG ES_HOST=elasticsearch
ARG ES_PORT=9200
ARG CURATOR_TIMEOUT=120
ARG CURATOR_MASTER_ONLY=False
ARG CURATOR_LOGLEVEL=INFO
ARG CURATOR_LOGFORMAT=default
ARG CURATOR_TIME_SOURCE=name

ARG CURATOR_CLOSE_UNITS=years
ARG CURATOR_CLOSE_COUNT=10
ARG CURATOR_DELETE_UNITS=years
ARG CURATOR_DELETE_COUNT=99
ARG CURATOR_DELETE_GIGS=1000000
ARG CURATOR_SNAPSHOT_REPO=logs
ARG CURATOR_SNAPSHOT_COMPRESSED=false
ARG CURATOR_SNAPSHOT_DISABLED=True

ENV ES_HOST $ES_HOST
ENV ES_PORT $ES_PORT
ENV CURATOR_TIMEOUT $CURATOR_TIMEOUT
ENV CURATOR_MASTER_ONLY $CURATOR_MASTER_ONLY
ENV CURATOR_LOGLEVEL $CURATOR_LOGLEVEL
ENV CURATOR_LOGFORMAT $CURATOR_LOGFORMAT
ENV CURATOR_TIME_SOURCE $CURATOR_TIME_SOURCE

ENV CURATOR_CLOSE_UNITS $CURATOR_CLOSE_UNITS
ENV CURATOR_CLOSE_COUNT $CURATOR_CLOSE_COUNT
ENV CURATOR_DELETE_UNITS $CURATOR_DELETE_UNITS
ENV CURATOR_DELETE_COUNT $CURATOR_DELETE_COUNT
ENV CURATOR_DELETE_GIGS $CURATOR_DELETE_GIGS
ENV CURATOR_SNAPSHOT_REPO $CURATOR_SNAPSHOT_REPO
ENV CURATOR_SNAPSHOT_COMPRESSED $CURATOR_SNAPSHOT_COMPRESSED
ENV CURATOR_SNAPSHOT_DISABLED $CURATOR_SNAPSHOT_DISABLED

ENV DEBIAN_FRONTEND noninteractive
ENV CURATOR_VERSION "5.7.6"
ENV CRON "5 0 * * *"
ENV CONFIG_FILE "/config/config_file.yml"
ENV ACTION_FILE "/config/action_file.yml"
ENV CURATOR_USER "curator"

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
    apt-get update && \
    apt-get  -y -q install \
      build-essential \
      cron \
      curl \
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
    bash -c 'echo -e "${CRON} su -c \"/usr/local/bin/curator --config ${CONFIG_FILE} ${ACTION_FILE}\" ${CURATOR_USER} >/proc/1/fd/1 2>/proc/1/fd/2\n@reboot su -c \"/usr/local/bin/elastic_search_status.sh && /usr/local/bin/register-elasticsearch-snapshot-repo.sh\" ${CURATOR_USER} >/proc/1/fd/1 2>/proc/1/fd/2" | crontab -'

ADD shared/bin/cron_env_deb.sh /usr/local/bin/
ADD shared/bin/elastic_search_status.sh /usr/local/bin/
ADD curator/scripts /usr/local/bin/
ADD curator/config /config/

CMD ["/usr/local/bin/cron_env_deb.sh"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
