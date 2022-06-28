FROM alpine:3.16

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
ARG OPENSEARCH_DEFAULT_DASHBOARD="0ad3d7c2-3441-485e-9dfe-dbb22e84e576"
ARG DASHBOARDS_URL="http://dashboards:5601/dashboards"

ENV ARKIME_INDEX_PATTERN $ARKIME_INDEX_PATTERN
ENV ARKIME_INDEX_PATTERN_ID $ARKIME_INDEX_PATTERN_ID
ENV ARKIME_INDEX_TIME_FIELD $ARKIME_INDEX_TIME_FIELD
ENV CREATE_OS_ARKIME_SESSION_INDEX $CREATE_OS_ARKIME_SESSION_INDEX
ENV OPENSEARCH_URL $OPENSEARCH_URL
ENV ISM_SNAPSHOT_COMPRESSED $ISM_SNAPSHOT_COMPRESSED
ENV ISM_SNAPSHOT_REPO $ISM_SNAPSHOT_REPO
ENV OFFLINE_REGION_MAPS_PORT $OFFLINE_REGION_MAPS_PORT
ENV OPENSEARCH_DEFAULT_DASHBOARD $OPENSEARCH_DEFAULT_DASHBOARD
ENV DASHBOARDS_URL $DASHBOARDS_URL
ENV PATH="/data:${PATH}"

ENV SUPERCRONIC_VERSION "0.2.1"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "d7f4c0886eb85249ad05ed592902fa6865bb9d70"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ENV ECS_RELEASES_URL "https://api.github.com/repos/elastic/ecs/releases/latest"

ADD dashboards/dashboards /opt/dashboards
ADD dashboards/anomaly_detectors /opt/anomaly_detectors
ADD dashboards/alerting /opt/alerting
ADD dashboards/notifications /opt/notifications
ADD dashboards/maps /opt/maps
ADD dashboards/scripts /data/
ADD dashboards/supervisord.conf /etc/supervisord.conf
ADD dashboards/templates /opt/templates
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/opensearch_status.sh /data/
ADD shared/bin/opensearch_index_size_prune.py /data/
ADD shared/bin/opensearch_read_only.py /data/

RUN apk update --no-cache && \
    apk upgrade --no-cache && \
    apk --no-cache add bash python3 py3-pip curl procps psmisc npm shadow jq && \
    npm install -g http-server && \
    pip3 install supervisor humanfriendly requests && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
      echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
      chmod +x "$SUPERCRONIC" && \
      mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
      ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic && \
    addgroup -g ${DEFAULT_GID} ${PGROUP} ; \
      adduser -D -H -u ${DEFAULT_UID} -h /nonexistant -s /sbin/nologin -G ${PGROUP} -g ${PUSER} ${PUSER} ; \
      addgroup ${PUSER} tty ; \
      addgroup ${PUSER} shadow ; \
    mkdir -p /data/init /opt/ecs && \
      cd /opt && \
      curl -sSL "$(curl -sSL "$ECS_RELEASES_URL" | jq '.tarball_url' | tr -d '"')" | tar xzf - -C ./ecs --strip-components 1 && \
      mv /opt/ecs/generated/elasticsearch /opt/ecs-templates && \
      find /opt/ecs-templates -name "*.json" -exec sed -i 's/\("type"[[:space:]]*:[[:space:]]*\)"match_only_text"/\1"text"/' "{}" \; && \
      find /opt/ecs-templates -name "*.json" -exec sed -i 's/\("type"[[:space:]]*:[[:space:]]*\)"constant_keyword"/\1"keyword"/' "{}" \; && \
      find /opt/ecs-templates -name "*.json" -exec sed -i 's/\("type"[[:space:]]*:[[:space:]]*\)"wildcard"/\1"keyword"/' "{}" \; && \
      find /opt/ecs-templates -name "*.json" -exec sed -i 's/\("type"[[:space:]]*:[[:space:]]*\)"flattened"/\1"nested"/' "{}" \; && \
      rm -rf /opt/ecs && \
    chown -R ${PUSER}:${PGROUP} /opt/dashboards /opt/templates /opt/ecs-templates /opt/maps /data/init /opt/anomaly_detectors && \
    chmod 755 /data/*.sh /data/*.py /data/init && \
    chmod 400 /opt/maps/* && \
    (echo -e "*/2 * * * * /data/create-arkime-sessions-index.sh\n0 10 * * * /data/index-refresh.py --template malcolm_template --unassigned\n30 */2 * * * /data/index-refresh.py --index 'malcolm_beats_*' --template malcolm_beats_template --unassigned\n*/20 * * * * /data/opensearch_index_size_prune.py" > ${SUPERCRONIC_CRONTAB})

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
