#FROM debian:12-slim
FROM python:3.13.5-bookworm

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/filescan'
LABEL org.opencontainers.image.description='Malcolm container for scanning files extracted by Zeek'

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

################################################################################

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "scan"
ENV PGROUP "scan"
ENV PUSER_PRIV_DROP true
# see PUSER_CHOWN at the bottom of the file (after the other environment variables it references)
USER root

################################################################################

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

################################################################################

ARG REDIS_CACHE_HOST=redis-cache
ARG REDIS_CACHE_PORT=6379
ARG FILESCAN_REDIS_DB=0
ARG REDIS_HOST=redis
ARG REDIS_PORT=6379
ARG LOGSTASH_ZEEK_REDIS_DB=0
ARG STRELKA_HOST=strelka-frontend
ARG STRELKA_PORT=57314
ARG FILESCAN_HEALTH_PORT=8001

ARG ZEEK_EXTRACTOR_PATH=/zeek/extract_files
#ARG ZEEK_LOG_DIRECTORY=/zeek/logs

#ARG EXTRACTED_FILE_IGNORE_EXISTING=false
#ARG EXTRACTED_FILE_LOGGER_START_SLEEP=5
#ARG EXTRACTED_FILE_MAX_BYTES=134217728
#ARG EXTRACTED_FILE_MIN_BYTES=64
#ARG EXTRACTED_FILE_PIPELINE_VERBOSITY=""
#ARG EXTRACTED_FILE_PRESERVATION=quarantined
#ARG EXTRACTED_FILE_PRUNE_INTERVAL_SECONDS=300
#ARG EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE=1TB
#ARG EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT=0
#ARG EXTRACTED_FILE_SCANNER_START_SLEEP=10
#ARG EXTRACTED_FILE_UPDATE_RULES=false
#ARG EXTRACTED_FILE_WATCHER_POLLING_ASSUME_CLOSED_SEC=10
#ARG EXTRACTED_FILE_WATCHER_POLLING=false
#ARG EXTRACTED_FILE_WATCHER_START_SLEEP=30

#ARG EXTRACTED_FILE_HTTP_SERVER_DEBUG=false
#ARG EXTRACTED_FILE_HTTP_SERVER_ENABLE=false
#ARG EXTRACTED_FILE_HTTP_SERVER_KEY=infected
#ARG EXTRACTED_FILE_HTTP_SERVER_PORT=8440
#ARG EXTRACTED_FILE_HTTP_SERVER_RECURSIVE=true
#ARG EXTRACTED_FILE_HTTP_SERVER_ZIP=true

################################################################################

ENV SUPERCRONIC_VERSION "0.2.33"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ENV REDIS_CACHE_HOST $REDIS_CACHE_HOST
ENV REDIS_CACHE_PORT $REDIS_CACHE_PORT
ENV FILESCAN_REDIS_DB $FILESCAN_REDIS_DB
ENV REDIS_HOST $REDIS_HOST
ENV REDIS_PORT $REDIS_PORT
ENV LOGSTASH_ZEEK_REDIS_DB $LOGSTASH_ZEEK_REDIS_DB
ENV STRELKA_HOST $STRELKA_HOST
ENV STRELKA_PORT $STRELKA_PORT
ENV FILESCAN_HEALTH_PORT $FILESCAN_HEALTH_PORT

ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH
#ENV ZEEK_LOG_DIRECTORY $ZEEK_LOG_DIRECTORY

#ENV SRC_BASE_DIR "/usr/local/src"

#ENV EXTRACTED_FILE_IGNORE_EXISTING $EXTRACTED_FILE_IGNORE_EXISTING
#ENV EXTRACTED_FILE_LOGGER_START_SLEEP $EXTRACTED_FILE_LOGGER_START_SLEEP
#ENV EXTRACTED_FILE_MAX_BYTES $EXTRACTED_FILE_MAX_BYTES
#ENV EXTRACTED_FILE_MIN_BYTES $EXTRACTED_FILE_MIN_BYTES
#ENV EXTRACTED_FILE_PIPELINE_VERBOSITY $EXTRACTED_FILE_PIPELINE_VERBOSITY
#ENV EXTRACTED_FILE_PRESERVATION $EXTRACTED_FILE_PRESERVATION
#ENV EXTRACTED_FILE_PRUNE_INTERVAL_SECONDS $EXTRACTED_FILE_PRUNE_INTERVAL_SECONDS
#ENV EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE $EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE
#ENV EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT $EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT
#ENV EXTRACTED_FILE_SCANNER_START_SLEEP $EXTRACTED_FILE_SCANNER_START_SLEEP
#ENV EXTRACTED_FILE_UPDATE_RULES $EXTRACTED_FILE_UPDATE_RULES
#ENV EXTRACTED_FILE_WATCHER_POLLING $EXTRACTED_FILE_WATCHER_POLLING
#ENV EXTRACTED_FILE_WATCHER_POLLING_ASSUME_CLOSED_SEC $EXTRACTED_FILE_WATCHER_POLLING_ASSUME_CLOSED_SEC
#ENV EXTRACTED_FILE_WATCHER_START_SLEEP $EXTRACTED_FILE_WATCHER_START_SLEEP

#ENV EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR "/opt/assets"
#ENV EXTRACTED_FILE_HTTP_SERVER_DEBUG $EXTRACTED_FILE_HTTP_SERVER_DEBUG
#ENV EXTRACTED_FILE_HTTP_SERVER_ENABLE $EXTRACTED_FILE_HTTP_SERVER_ENABLE
#ENV EXTRACTED_FILE_HTTP_SERVER_ZIP $EXTRACTED_FILE_HTTP_SERVER_ZIP
#ENV EXTRACTED_FILE_HTTP_SERVER_KEY $EXTRACTED_FILE_HTTP_SERVER_KEY
#ENV EXTRACTED_FILE_HTTP_SERVER_RECURSIVE $EXTRACTED_FILE_HTTP_SERVER_RECURSIVE
#ENV EXTRACTED_FILE_HTTP_SERVER_PORT $EXTRACTED_FILE_HTTP_SERVER_PORT

################################################################################

# add our user/group very first, since it isn't likely to change (and if it
# does, we ought to redo a lot of steps)
RUN set -e ; \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} ; \
    useradd -m --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} ; \
    usermod -a -G tty ${PUSER}

################################################################################

# fix our package lists, upgrade, and install a few minimal dependencies
RUN set -e ; \
    sed -i /etc/apt/sources.list.d/debian.sources \
      -e 's/main$/main contrib non-free/' ; \
    apt-get update -q ; \
    apt-get upgrade -y -q \
      --no-install-recommends ; \
    apt-get install -y -q \
      --no-install-recommends \
      bc \
      ca-certificates \
      curl \
      rsync \
      tini \
      unzip

################################################################################

# add supercronic early on because it's also unlikely to change
RUN set -e ; \
    export BINARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') ; \
    curl -fsSL -o /usr/local/bin/supercronic "${SUPERCRONIC_URL}${BINARCH}" ; \
    chmod +x /usr/local/bin/supercronic

################################################################################

# install the rest of our build/run dependencies
RUN set -e ; \
    apt-get update -q ; \
    apt-get install -y -q \
      --no-install-recommends \
      automake \
      gcc \
      git \
      inotify-tools \
      jq \
      libjansson4 \
      libjansson-dev \
      libmagic1 \
      libmagic-dev \
      libssl3 \
      libssl-dev \
      libtool \
      make \
      pkg-config \
      psmisc \
      python3 \
      python3-dev \
      python3-pip \
      python3-venv \
      webfs

################################################################################

COPY --chmod=755 \
    filescan/docker-entrypoint.sh \
    /docker-entrypoint.sh
COPY --chmod=755 \
    shared/bin/docker-uid-gid-setup.sh \
    shared/bin/service_check_passthrough.sh \
    /usr/local/bin/
# originally also copied: shared/bin/prune_files.sh

RUN mkdir -p /install-filescan
COPY --chmod=644 \
    filescan/python-filescan \
    /install-filescan/
RUN cd /install-filescan && \
    python3 -m pip install --break-system-packages --no-cache-dir -r Requirements.txt && \
    make && \
    python3 -m pip install --break-system-packages --no-cache-dir .
RUN rm -rf /install-filescan

################################################################################

# clean up our build dependencies
RUN set -e ; \
    apt-get remove -y -q \
      --allow-downgrades \
      --allow-remove-essential \
      --allow-change-held-packages \
      --purge \
      automake \
      build-essential \
      gcc \
      gcc-12 \
      libc6-dev \
      libgcc-12-dev \
      libjansson-dev \
      libmagic-dev \
      libssl-dev \
      libtool \
      make \
      python3-dev \
      python3-venv ; \
    apt-get autoremove -y -q \
      --allow-downgrades \
      --allow-remove-essential \
      --allow-change-held-packages ; \
    apt-get clean ; \
    rm -rf /var/lib/apt/lists/* /tmp/*

################################################################################

# copy the most-likely-to-change files last
RUN mkdir -p /filescan /filescan/data/files /filescan/data/logs
COPY --chmod=644 \
    filescan/supervisord.conf /etc/supervisord.conf
COPY --chmod=644 \
    filescan/filescan-config.yml /filescan/filescan-config.yml

################################################################################

WORKDIR /filescan

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "filescan", \
            "/docker-entrypoint.sh"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]

