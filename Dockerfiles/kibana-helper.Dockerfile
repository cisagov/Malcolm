FROM alpine:3.12

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
LABEL org.opencontainers.image.title='malcolmnetsec/kibana-helper'
LABEL org.opencontainers.image.description='Malcolm container providing Kibana support functions'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "helper"
ENV PGROUP "helper"
ENV PUSER_PRIV_DROP true

ENV TERM xterm

ARG ARKIME_INDEX_PATTERN="sessions2-*"
ARG ARKIME_INDEX_PATTERN_ID="sessions2-*"
ARG ARKIME_INDEX_TIME_FIELD="firstPacket"
ARG CREATE_ES_ARKIME_SESSION_INDEX="true"
ARG ELASTICSEARCH_URL="http://elasticsearch:9200"
ARG ISM_SNAPSHOT_COMPRESSED=false
ARG ISM_SNAPSHOT_REPO=logs
ARG KIBANA_OFFLINE_REGION_MAPS_PORT="28991"
ARG KIBANA_URL="http://kibana:5601/kibana"

ENV ARKIME_INDEX_PATTERN $ARKIME_INDEX_PATTERN
ENV ARKIME_INDEX_PATTERN_ID $ARKIME_INDEX_PATTERN_ID
ENV ARKIME_INDEX_TIME_FIELD $ARKIME_INDEX_TIME_FIELD
ENV CREATE_ES_ARKIME_SESSION_INDEX $CREATE_ES_ARKIME_SESSION_INDEX
ENV ELASTICSEARCH_URL $ELASTICSEARCH_URL
ENV ISM_SNAPSHOT_COMPRESSED $ISM_SNAPSHOT_COMPRESSED
ENV ISM_SNAPSHOT_REPO $ISM_SNAPSHOT_REPO
ENV KIBANA_OFFLINE_REGION_MAPS_PORT $KIBANA_OFFLINE_REGION_MAPS_PORT
ENV KIBANA_URL $KIBANA_URL
ENV PATH="/data:${PATH}"

ENV SUPERCRONIC_VERSION "0.1.12"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "048b95b48b708983effb2e5c935a1ef8483d9e3e"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ADD kibana/dashboards /opt/kibana/dashboards
ADD kibana/maps /opt/maps
ADD kibana/scripts /data/
ADD kibana/supervisord.conf /etc/supervisord.conf
ADD kibana/zeek_template.json /data/zeek_template.json
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/elastic_search_status.sh /data/
ADD shared/bin/elastic_index_size_prune.py /data/

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
    chown -R ${PUSER}:${PGROUP} /opt/kibana/dashboards /opt/maps /data/init && \
    chmod 755 /data/*.sh /data/*.py /data/init && \
    chmod 400 /opt/maps/* && \
    (echo -e "*/2 * * * * /data/kibana-create-moloch-sessions-index.sh\n0 10 * * * /data/kibana_index_refresh.py --template zeek_template\n*/20 * * * * /data/elastic_index_size_prune.py" > ${SUPERCRONIC_CRONTAB})

EXPOSE $KIBANA_OFFLINE_REGION_MAPS_PORT

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
