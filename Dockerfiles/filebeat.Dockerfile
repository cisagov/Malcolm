FROM docker.elastic.co/beats/filebeat-oss:8.19.2

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/filebeat-oss'
LABEL org.opencontainers.image.description='Malcolm container providing Filebeat (the Apache-licensed variant)'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "filebeat"
ENV PGROUP "filebeat"
# This is to handle an issue when running with rootless podman and
#   "userns_mode: keep-id". It seems that anything defined as a VOLUME
#   in the Dockerfile is getting set with an ownership of 999:999.
#   This is to override that, although I'm not yet sure if there are
#   other implications. See containers/podman#23347.
ENV PUSER_CHOWN "/usr/share/filebeat-logs/data;/usr/share/filebeat-nginx/data;/usr/share/filebeat-tcp/data"
# not dropping privileges globally: supervisord will take care of it
# on a case-by-case basis so that one script (filebeat-watch-zeeklogs-uploads-folder.py)
# can chown uploaded files
ENV PUSER_PRIV_DROP false
USER root

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ARG AUTO_TAG=true
ARG FILEBEAT_SCAN_FREQUENCY=10s
ARG FILEBEAT_CLEAN_INACTIVE=180m
ARG FILEBEAT_IGNORE_OLDER=120m
ARG FILEBEAT_CLOSE_INACTIVE=120s
ARG FILEBEAT_CLOSE_RENAMED=true
ARG FILEBEAT_CLOSE_REMOVED=true
ARG FILEBEAT_CLOSE_EOF=true
ARG FILEBEAT_CLEAN_REMOVED=true
ARG FILEBEAT_ZEEK_LOG_PATH="/zeek/current"
ARG FILEBEAT_ZEEK_LOG_LIVE_PATH="/zeek/live"
ARG FILEBEAT_SURICATA_LOG_PATH="/suricata"
ARG FILEBEAT_NGINX_LOG_PATH="/nginx"
ARG FILEBEAT_WATCHER_POLLING=false
ARG FILEBEAT_WATCHER_POLLING_ASSUME_CLOSED_SEC=10
ARG LOG_CLEANUP_MINUTES=0
ARG ZIP_CLEANUP_MINUTES=0
ARG NGINX_LOG_ACCESS_AND_ERRORS=false
ARG FILEBEAT_TCP_LISTEN=false
ARG FILEBEAT_TCP_PORT=5045
ARG FILEBEAT_TCP_LOG_FORMAT="raw"
ARG FILEBEAT_TCP_MAX_CONNECTIONS=32
ARG FILEBEAT_TCP_MAX_MESSAGE_SIZE=20MB
ARG FILEBEAT_TCP_PARSE_ADD_ERROR_KEY=true
ARG FILEBEAT_TCP_PARSE_DOCUMENT_ID_FIELD=""
ARG FILEBEAT_TCP_PARSE_MAX_DEPTH=1
ARG FILEBEAT_TCP_PARSE_OVERWRITE_KEYS=false
ARG FILEBEAT_TCP_PARSE_PROCESS_ARRAY=false
ARG FILEBEAT_TCP_PARSE_SOURCE_FIELD="message"
ARG FILEBEAT_TCP_PARSE_TARGET_FIELD=""
ARG FILEBEAT_TCP_PARSE_DROP_FIELD=""
ARG FILEBEAT_TCP_TAG="_malcolm_beats"
ARG FILEBEAT_SYSLOG_TCP_LISTEN=false
ARG FILEBEAT_SYSLOG_UDP_LISTEN=false
ARG PCAP_NODE_NAME=malcolm

ENV SUPERCRONIC_VERSION "0.2.40"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ENV YQ_VERSION "4.49.2"
ENV YQ_URL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_"

ENV EVTX_VERSION "0.9.0"
ENV EVTX_URL "https://github.com/omerbenamram/evtx/releases/download/v${EVTX_VERSION}/evtx_dump-v${EVTX_VERSION}-XXX-unknown-linux-gnu"

USER root

ADD --chmod=644 filebeat/requirements.txt /usr/local/src/

RUN export EVTXARCH=$(uname -m | sed 's/arm64/aarch64/') && \
    export BINARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install \
        bzip2 \
        cpio \
        curl \
        file \
        git \
        gzip \
        inotify-tools \
        lzma \
        jq \
        jo \
        openssl \
        p7zip \
        p7zip-full \
        p7zip-rar \
        psmisc \
        python3-pip \
        python3-setuptools \
        python3 \
        rsync \
        tar \
        tini \
        unar \
        unzip \
        xz-utils && \
    python3 -m pip install --no-compile --no-cache-dir --break-system-packages -r /usr/local/src/requirements.txt && \
    curl -fsSL -o /usr/local/bin/supercronic "${SUPERCRONIC_URL}${BINARCH}" && \
      chmod +x /usr/local/bin/supercronic && \
    curl -fsSL -o /usr/local/bin/yq "${YQ_URL}${BINARCH}" && \
        chmod 755 /usr/local/bin/yq && \
    curl -fsSL -o /usr/local/bin/evtx "$(echo "${EVTX_URL}" | sed "s/XXX/${EVTXARCH}/g")" && \
        chmod 755 /usr/local/bin/evtx && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove git && \
        apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/filebeat.sh /usr/local/bin/container_health.sh
ADD --chmod=644 filebeat/filebeat-logs.yml /usr/share/filebeat-logs/filebeat-logs.yml
ADD --chmod=644 filebeat/filebeat-nginx.yml /usr/share/filebeat-nginx/filebeat-nginx.yml
ADD --chmod=644 filebeat/filebeat-tcp.yml /usr/share/filebeat-tcp/filebeat-tcp.yml
ADD --chmod=644 filebeat/filebeat-syslog-udp.yml /usr/share/filebeat-syslog-udp/filebeat-syslog-udp.yml
ADD --chmod=644 filebeat/filebeat-syslog-tcp.yml /usr/share/filebeat-syslog-tcp/filebeat-syslog-tcp.yml
ADD filebeat/scripts /usr/local/bin/
ADD --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_constants.py /usr/local/bin/
ADD --chmod=644 shared/bin/watch_common.py /usr/local/bin/
ADD --chmod=755 shared/bin/opensearch_status.sh /usr/local/bin/
ADD --chmod=644 filebeat/supervisord.conf /etc/supervisord.conf

RUN for INPUT in logs nginx tcp syslog-tcp syslog-udp; do \
      mkdir -p /usr/share/filebeat-$INPUT/data; \
      chown -R root:${PGROUP} /usr/share/filebeat-$INPUT; \
      cp -a /usr/share/filebeat/module /usr/share/filebeat-$INPUT/module; \
      chmod 770 /usr/share/filebeat-$INPUT; \
      chmod 770 /usr/share/filebeat-$INPUT/data; \
    done; \
    chmod 755 /usr/local/bin/*.sh /usr/local/bin/*.py && \
    (echo "* * * * * /usr/local/bin/filebeat-process-zeek-folder.sh\n* * * * * /usr/local/bin/clean-processed-folder.py" > ${SUPERCRONIC_CRONTAB})

ENV AUTO_TAG $AUTO_TAG
ENV LOG_CLEANUP_MINUTES $LOG_CLEANUP_MINUTES
ENV ZIP_CLEANUP_MINUTES $ZIP_CLEANUP_MINUTES
ENV FILEBEAT_WATCHER_POLLING $FILEBEAT_WATCHER_POLLING
ENV FILEBEAT_WATCHER_POLLING_ASSUME_CLOSED_SEC $FILEBEAT_WATCHER_POLLING_ASSUME_CLOSED_SEC
ENV FILEBEAT_SCAN_FREQUENCY $FILEBEAT_SCAN_FREQUENCY
ENV FILEBEAT_CLEAN_INACTIVE $FILEBEAT_CLEAN_INACTIVE
ENV FILEBEAT_IGNORE_OLDER $FILEBEAT_IGNORE_OLDER
ENV FILEBEAT_CLOSE_INACTIVE $FILEBEAT_CLOSE_INACTIVE
ENV FILEBEAT_CLOSE_RENAMED $FILEBEAT_CLOSE_RENAMED
ENV FILEBEAT_CLOSE_REMOVED $FILEBEAT_CLOSE_REMOVED
ENV FILEBEAT_CLOSE_EOF $FILEBEAT_CLOSE_EOF
ENV FILEBEAT_CLEAN_REMOVED $FILEBEAT_CLEAN_REMOVED
ENV FILEBEAT_ZEEK_LOG_PATH $FILEBEAT_ZEEK_LOG_PATH
ENV FILEBEAT_ZEEK_LOG_LIVE_PATH $FILEBEAT_ZEEK_LOG_LIVE_PATH
ENV FILEBEAT_SURICATA_LOG_PATH $FILEBEAT_SURICATA_LOG_PATH
ENV FILEBEAT_NGINX_LOG_PATH $FILEBEAT_NGINX_LOG_PATH
ENV NGINX_LOG_ACCESS_AND_ERRORS $NGINX_LOG_ACCESS_AND_ERRORS
ENV FILEBEAT_TCP_LISTEN $FILEBEAT_TCP_LISTEN
ENV FILEBEAT_TCP_PORT $FILEBEAT_TCP_PORT
ENV FILEBEAT_TCP_LOG_FORMAT $FILEBEAT_TCP_LOG_FORMAT
ENV FILEBEAT_TCP_MAX_CONNECTIONS $FILEBEAT_TCP_MAX_CONNECTIONS
ENV FILEBEAT_TCP_MAX_MESSAGE_SIZE $FILEBEAT_TCP_MAX_MESSAGE_SIZE
ENV FILEBEAT_TCP_PARSE_ADD_ERROR_KEY $FILEBEAT_TCP_PARSE_ADD_ERROR_KEY
ENV FILEBEAT_TCP_PARSE_DOCUMENT_ID_FIELD $FILEBEAT_TCP_PARSE_DOCUMENT_ID_FIELD
ENV FILEBEAT_TCP_PARSE_MAX_DEPTH $FILEBEAT_TCP_PARSE_MAX_DEPTH
ENV FILEBEAT_TCP_PARSE_OVERWRITE_KEYS $FILEBEAT_TCP_PARSE_OVERWRITE_KEYS
ENV FILEBEAT_TCP_PARSE_PROCESS_ARRAY $FILEBEAT_TCP_PARSE_PROCESS_ARRAY
ENV FILEBEAT_TCP_PARSE_SOURCE_FIELD $FILEBEAT_TCP_PARSE_SOURCE_FIELD
ENV FILEBEAT_TCP_PARSE_TARGET_FIELD $FILEBEAT_TCP_PARSE_TARGET_FIELD
ENV FILEBEAT_TCP_PARSE_DROP_FIELD $FILEBEAT_TCP_PARSE_DROP_FIELD
ENV FILEBEAT_TCP_TAG $FILEBEAT_TCP_TAG
ENV FILEBEAT_SYSLOG_TCP_LISTEN $FILEBEAT_SYSLOG_TCP_LISTEN
ENV FILEBEAT_SYSLOG_UDP_LISTEN $FILEBEAT_SYSLOG_UDP_LISTEN
ENV FILEBEAT_REGISTRY_FILE "/usr/share/filebeat-logs/data/registry/filebeat/log.json"
ENV FILEBEAT_ZEEK_DIR "/zeek/"
ENV FILEBEAT_ZEEK_UPLOAD_SUBDIR "upload"
ENV PCAP_NODE_NAME $PCAP_NODE_NAME

# see PUSER_CHOWN comment above
VOLUME ["/usr/share/filebeat-logs/data", "/usr/share/filebeat-nginx/data", "/usr/share/filebeat-tcp/data"]

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "filebeat"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION
ENV BUILD_DATE $BUILD_DATE
ENV MALCOLM_VERSION $MALCOLM_VERSION
ENV VCS_REVISION $VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
