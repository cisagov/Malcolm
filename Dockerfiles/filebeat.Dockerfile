FROM docker.elastic.co/beats/filebeat-oss:6.8.5

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/filebeat-oss'
LABEL org.opencontainers.image.description='Malcolm container providing Filebeat (the Apache-licensed variant)'


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
ARG AUTO_TAG=true

USER root

RUN yum install -y epel-release && \
    yum update -y && \
    yum install -y cronie inotify-tools file psmisc tar gzip unzip cpio bzip2 lzma xz p7zip p7zip-plugins unar python-setuptools python-pip && \
    yum clean all && \
    easy_install supervisor && \
    pip install patool entrypoint2 pyunpack python-magic ordered-set && \
    ln -sr /usr/sbin/fuser /bin/fuser

ADD shared/bin/cron_env_centos.sh /data/
ADD filebeat/filebeat.yml /usr/share/filebeat/filebeat.yml
ADD filebeat/scripts /data/
ADD filebeat/supervisord.conf /etc/supervisord.conf
RUN chmod 755 /data/*.sh /data/*.py && \
    mkdir -p /var/log/supervisor && \
    (echo -e "* * * * * su -c /data/filebeat-process-zeek-folder.sh filebeat >/dev/null 2>&1\n*/5 * * * * su -c /data/filebeat-clean-zeeklogs-processed-folder.py filebeat >/dev/null 2>&1" | crontab -)

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
ENV AUTO_TAG $AUTO_TAG

ENV FILEBEAT_REGISTRY_FILE "/usr/share/filebeat/data/registry"
ENV FILEBEAT_ZEEK_DIR "/data/zeek/"
ENV PATH="/data:${PATH}"

VOLUME ["/usr/share/filebeat/data"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
