FROM docker.elastic.co/beats/filebeat-oss:7.10.0

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
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

ARG FILEBEAT_LOG_CLEANUP_MINUTES=0
ARG FILEBEAT_ZIP_CLEANUP_MINUTES=0
ARG FILEBEAT_SCAN_FREQUENCY=10s
ARG FILEBEAT_CLEAN_INACTIVE=45m
ARG FILEBEAT_IGNORE_OLDER=30m
ARG FILEBEAT_CLOSE_INACTIVE=30s
ARG FILEBEAT_CLOSE_RENAMED=true
ARG FILEBEAT_CLOSE_REMOVED=true
ARG FILEBEAT_CLOSE_EOF=true
ARG FILEBEAT_CLEAN_REMOVED=true
ARG FILEBEAT_LOG_PATH="/data/zeek/current"
ARG FILEBEAT_NGINX_LOG_PATH="/data/nginx"
ARG NGINX_LOG_ACCESS_AND_ERRORS=false
ARG AUTO_TAG=true

ENV SUPERCRONIC_VERSION "0.1.12"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "048b95b48b708983effb2e5c935a1ef8483d9e3e"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

USER root

RUN yum install -y epel-release && \
        yum update -y && \
        yum install -y curl inotify-tools file psmisc tar gzip unzip cpio bzip2 lzma xz p7zip p7zip-plugins unar python-setuptools python-pip && \
        yum clean all && \
    ln -sr /usr/sbin/fuser /bin/fuser && \
    easy_install supervisor && \
    pip install patool entrypoint2 pyunpack python-magic ordered-set==3.1.1 && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
      echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
      chmod +x "$SUPERCRONIC" && \
      mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
      ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD filebeat/filebeat.yml /usr/share/filebeat/filebeat.yml
ADD filebeat/filebeat-nginx.yml /usr/share/filebeat-nginx/filebeat-nginx.yml
ADD filebeat/scripts /data/
ADD shared/bin/elastic_search_status.sh /data/
ADD filebeat/supervisord.conf /etc/supervisord.conf
RUN mkdir -p /usr/share/filebeat-nginx/data && \
    chown -R root:${PGROUP} /usr/share/filebeat-nginx && \
    cp -a /usr/share/filebeat/module /usr/share/filebeat-nginx/module && \
    chmod 750 /usr/share/filebeat-nginx && \
    chmod 770 /usr/share/filebeat-nginx/data && \
    chmod 755 /data/*.sh /data/*.py && \
    (echo -e "* * * * * /data/filebeat-process-zeek-folder.sh\n*/5 * * * * /data/filebeat-clean-zeeklogs-processed-folder.py" > ${SUPERCRONIC_CRONTAB})

ENV FILEBEAT_LOG_CLEANUP_MINUTES $FILEBEAT_LOG_CLEANUP_MINUTES
ENV FILEBEAT_ZIP_CLEANUP_MINUTES $FILEBEAT_ZIP_CLEANUP_MINUTES
ENV FILEBEAT_SCAN_FREQUENCY $FILEBEAT_SCAN_FREQUENCY
ENV FILEBEAT_CLEAN_INACTIVE $FILEBEAT_CLEAN_INACTIVE
ENV FILEBEAT_IGNORE_OLDER $FILEBEAT_IGNORE_OLDER
ENV FILEBEAT_CLOSE_INACTIVE $FILEBEAT_CLOSE_INACTIVE
ENV FILEBEAT_CLOSE_RENAMED $FILEBEAT_CLOSE_RENAMED
ENV FILEBEAT_CLOSE_REMOVED $FILEBEAT_CLOSE_REMOVED
ENV FILEBEAT_CLOSE_EOF $FILEBEAT_CLOSE_EOF
ENV FILEBEAT_CLEAN_REMOVED $FILEBEAT_CLEAN_REMOVED
ENV FILEBEAT_LOG_PATH $FILEBEAT_LOG_PATH
ENV FILEBEAT_NGINX_LOG_PATH $FILEBEAT_NGINX_LOG_PATH
ENV NGINX_LOG_ACCESS_AND_ERRORS $NGINX_LOG_ACCESS_AND_ERRORS
ENV AUTO_TAG $AUTO_TAG

ENV FILEBEAT_REGISTRY_FILE "/usr/share/filebeat/data/registry/filebeat/data.json"
ENV FILEBEAT_ZEEK_DIR "/data/zeek/"
ENV PATH="/data:${PATH}"

VOLUME ["/usr/share/filebeat/data", "/usr/share/filebeat-nginx/data"]

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
