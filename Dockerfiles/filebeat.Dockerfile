FROM docker.elastic.co/beats/filebeat-oss:7.10.2

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/filebeat-oss'
LABEL org.opencontainers.image.description='Malcolm container providing Filebeat (the Apache-licensed variant)'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "filebeat"
ENV PGROUP "filebeat"
# not dropping privileges globally: supervisord will take care of it
# on a case-by-case basis so that one script (filebeat-watch-zeeklogs-uploads-folder.sh)
# can chown uploaded files
ENV PUSER_PRIV_DROP false

ENV TERM xterm

ARG AUTO_TAG=true
ARG FILEBEAT_SCAN_FREQUENCY=10s
ARG FILEBEAT_CLEAN_INACTIVE=180m
ARG FILEBEAT_IGNORE_OLDER=120m
ARG FILEBEAT_CLOSE_INACTIVE=120s
ARG FILEBEAT_CLOSE_RENAMED=true
ARG FILEBEAT_CLOSE_REMOVED=true
ARG FILEBEAT_CLOSE_EOF=true
ARG FILEBEAT_CLEAN_REMOVED=true
ARG FILEBEAT_ZEEK_LOG_PATH="/data/zeek/current"
ARG FILEBEAT_SURICATA_LOG_PATH="/data/suricata"
ARG FILEBEAT_NGINX_LOG_PATH="/data/nginx"
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
ARG FILEBEAT_TCP_TAG=""

ENV SUPERCRONIC_VERSION "0.2.1"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "d7f4c0886eb85249ad05ed592902fa6865bb9d70"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

USER root

RUN yum install -y epel-release && \
        yum upgrade -y && \
        yum install -y curl inotify-tools file psmisc tar gzip unzip cpio bzip2 lzma xz p7zip p7zip-plugins unar python3-setuptools python3-pip && \
        yum clean all && \
    ln -sr /usr/sbin/fuser /bin/fuser && \
    python3 -m pip install patool entrypoint2 pyunpack python-magic ordered-set supervisor && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
      echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
      chmod +x "$SUPERCRONIC" && \
      mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
      ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD filebeat/filebeat.yml /usr/share/filebeat/filebeat.yml
ADD filebeat/filebeat-nginx.yml /usr/share/filebeat-nginx/filebeat-nginx.yml
ADD filebeat/filebeat-tcp.yml /usr/share/filebeat-tcp/filebeat-tcp.yml
ADD filebeat/scripts /data/
ADD shared/bin/opensearch_status.sh /data/
ADD filebeat/supervisord.conf /etc/supervisord.conf
RUN for INPUT in nginx tcp; do \
      mkdir -p /usr/share/filebeat-$INPUT/data; \
      chown -R root:${PGROUP} /usr/share/filebeat-$INPUT; \
      cp -a /usr/share/filebeat/module /usr/share/filebeat-$INPUT/module; \
      chmod 750 /usr/share/filebeat-$INPUT; \
      chmod 770 /usr/share/filebeat-$INPUT/data; \
    done; \
    chmod 755 /data/*.sh /data/*.py && \
    (echo -e "* * * * * /data/filebeat-process-zeek-folder.sh\n*/5 * * * * /data/filebeat-clean-zeeklogs-processed-folder.py" > ${SUPERCRONIC_CRONTAB})

ENV AUTO_TAG $AUTO_TAG
ENV LOG_CLEANUP_MINUTES $LOG_CLEANUP_MINUTES
ENV ZIP_CLEANUP_MINUTES $ZIP_CLEANUP_MINUTES
ENV FILEBEAT_SCAN_FREQUENCY $FILEBEAT_SCAN_FREQUENCY
ENV FILEBEAT_CLEAN_INACTIVE $FILEBEAT_CLEAN_INACTIVE
ENV FILEBEAT_IGNORE_OLDER $FILEBEAT_IGNORE_OLDER
ENV FILEBEAT_CLOSE_INACTIVE $FILEBEAT_CLOSE_INACTIVE
ENV FILEBEAT_CLOSE_RENAMED $FILEBEAT_CLOSE_RENAMED
ENV FILEBEAT_CLOSE_REMOVED $FILEBEAT_CLOSE_REMOVED
ENV FILEBEAT_CLOSE_EOF $FILEBEAT_CLOSE_EOF
ENV FILEBEAT_CLEAN_REMOVED $FILEBEAT_CLEAN_REMOVED
ENV FILEBEAT_ZEEK_LOG_PATH $FILEBEAT_ZEEK_LOG_PATH
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
ENV FILEBEAT_REGISTRY_FILE "/usr/share/filebeat/data/registry/filebeat/data.json"
ENV FILEBEAT_ZEEK_DIR "/data/zeek/"
ENV PATH="/data:${PATH}"

VOLUME ["/usr/share/filebeat/data", "/usr/share/filebeat-nginx/data", "/usr/share/filebeat-tcp/data"]

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
