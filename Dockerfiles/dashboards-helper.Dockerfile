FROM alpine:3.14

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/dashboards-helper'
LABEL org.opencontainers.image.description='Malcolm container providing OpenSearch Dashboards support functions'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "helper"
ENV PGROUP "helper"
ENV PUSER_PRIV_DROP true

ENV TERM xterm

ARG ARKIME_INDEX_PATTERN="arkime_sessions3-*"
ARG ARKIME_INDEX_PATTERN_ID="arkime_sessions3-*"
ARG ARKIME_INDEX_TIME_FIELD="firstPacket"
ARG CREATE_OS_ARKIME_SESSION_INDEX="true"
ARG OPENSEARCH_URL="http://opensearch:9200"
ARG ISM_SNAPSHOT_COMPRESSED=false
ARG ISM_SNAPSHOT_REPO=logs
ARG OFFLINE_REGION_MAPS_PORT="28991"
ARG DASHBOARDS_URL="http://dashboards:5601/dashboards"

ENV ARKIME_INDEX_PATTERN $ARKIME_INDEX_PATTERN
ENV ARKIME_INDEX_PATTERN_ID $ARKIME_INDEX_PATTERN_ID
ENV ARKIME_INDEX_TIME_FIELD $ARKIME_INDEX_TIME_FIELD
ENV CREATE_OS_ARKIME_SESSION_INDEX $CREATE_OS_ARKIME_SESSION_INDEX
ENV OPENSEARCH_URL $OPENSEARCH_URL
ENV ISM_SNAPSHOT_COMPRESSED $ISM_SNAPSHOT_COMPRESSED
ENV ISM_SNAPSHOT_REPO $ISM_SNAPSHOT_REPO
ENV OFFLINE_REGION_MAPS_PORT $OFFLINE_REGION_MAPS_PORT
ENV DASHBOARDS_URL $DASHBOARDS_URL
ENV PATH="/data:${PATH}"

ENV SUPERCRONIC_VERSION "0.1.12"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "048b95b48b708983effb2e5c935a1ef8483d9e3e"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ADD dashboards/dashboards /opt/dashboards
ADD dashboards/anomaly_detectors /opt/anomaly_detectors
ADD dashboards/maps /opt/maps
ADD dashboards/scripts /data/
ADD dashboards/supervisord.conf /etc/supervisord.conf
ADD dashboards/zeek_template.json /data/zeek_template.json
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/opensearch_status.sh /data/
ADD shared/bin/opensearch_index_size_prune.py /data/

RUN apk --no-cache add bash python3 py3-pip curl procps psmisc npm shadow jq && \
    npm install -g http-server && \
    pip3 install supervisor humanfriendly && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
      echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
      chmod +x "$SUPERCRONIC" && \
      mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
      ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic && \
    addgroup -g ${DEFAULT_GID} ${PGROUP} ; \
      adduser -D -H -u ${DEFAULT_UID} -h /nonexistant -s /sbin/nologin -G ${PGROUP} -g ${PUSER} ${PUSER} ; \
      addgroup ${PUSER} tty ; \
      addgroup ${PUSER} shadow ; \
    mkdir -p /data/init && \
    chown -R ${PUSER}:${PGROUP} /opt/dashboards /opt/maps /data/init /opt/anomaly_detectors && \
    chmod 755 /data/*.sh /data/*.py /data/init && \
    chmod 400 /opt/maps/* && \
    (echo -e "*/2 * * * * /data/create-arkime-sessions-index.sh\n0 10 * * * /data/index-refresh.py --template zeek_template\n*/20 * * * * /data/opensearch_index_size_prune.py" > ${SUPERCRONIC_CRONTAB})

EXPOSE $OFFLINE_REGION_MAPS_PORT

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]

VOLUME ["/data/init"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
