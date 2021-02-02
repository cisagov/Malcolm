FROM debian:buster-slim

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/elastalert'
LABEL org.opencontainers.image.description='Malcolm container providing curation for Elasticsearch indices'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "curator"
ENV PGROUP "curator"
ENV PUSER_PRIV_DROP true

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

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

ENV SUPERCRONIC_VERSION "0.1.12"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "048b95b48b708983effb2e5c935a1ef8483d9e3e"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ENV CURATOR_VERSION "5.8.1"
ENV CRON "5 0 * * *"
ENV CONFIG_FILE "/config/config_file.yml"
ENV ACTION_FILE "/config/action_file.yml"

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
    apt-get update && \
    apt-get  -y -q install \
      build-essential \
      curl \
      libyaml-0-2 \
      libyaml-dev \
      procps \
      psmisc \
      python3 \
      python3-dev \
      python3-wheel \
      python3-pip && \
      # from https://github.com/elastic/curator/issues/1496#issuecomment-715262708
      python3 -m pip install "boto3<1.16" "botocore<1.19" && \
      python3 -m pip install elasticsearch-curator==${CURATOR_VERSION} && \
    groupadd --gid ${DEFAULT_GID} ${PUSER} && \
      useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} && \
    apt-get -q -y --purge remove guile-2.2-libs python3-dev build-essential libyaml-dev && \
      apt-get -q -y autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
      echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
      chmod +x "$SUPERCRONIC" && \
      mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
      ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic && \
    bash -c 'echo -e "${CRON} /usr/local/bin/curator --config ${CONFIG_FILE} ${ACTION_FILE}" > ${SUPERCRONIC_CRONTAB}'

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/elastic_search_status.sh /usr/local/bin/
ADD curator/scripts /usr/local/bin/
ADD curator/config /config/

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/local/bin/docker-entrypoint.sh"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
