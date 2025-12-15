FROM python:3.13-slim-trixie

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/filescan'
LABEL org.opencontainers.image.description='Malcolm container for scanning files extracted by Zeek'

################################################################################

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "scan"
ENV PGROUP "scan"
ENV PUSER_PRIV_DROP true
USER root

################################################################################

ARG STRELKA_HOST=strelka-frontend
ARG STRELKA_PORT=57314
ARG FILESCAN_HEALTH_PORT=8001
ARG FILESCAN_VERBOSITY=

ARG EXTRACTED_FILE_HTTP_SERVER_ENABLE=false
ARG EXTRACTED_FILE_HTTP_SERVER_ZIP=true
ARG EXTRACTED_FILE_HTTP_SERVER_KEY=infected
ARG EXTRACTED_FILE_HTTP_SERVER_RECURSIVE=true
ARG EXTRACTED_FILE_HTTP_SERVER_PORT=8006

ARG EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE=1TB
ARG EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT=0
ARG EXTRACTED_FILE_PRUNE_INTERVAL_SECONDS=300

################################################################################

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ENV SUPERCRONIC_VERSION "0.2.39"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ENV YQ_VERSION "4.50.1"
ENV YQ_URL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_"

ENV STRELKA_HOST $STRELKA_HOST
ENV STRELKA_PORT $STRELKA_PORT
ENV FILESCAN_HEALTH_PORT $FILESCAN_HEALTH_PORT
ENV FILESCAN_VERBOSITY $FILESCAN_VERBOSITY

ENV ZEEK_EXTRACTOR_PATH "/zeek/extract_files"

ENV EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR "/opt/assets"
ENV EXTRACTED_FILE_HTTP_SERVER_ENABLE $EXTRACTED_FILE_HTTP_SERVER_ENABLE
ENV EXTRACTED_FILE_HTTP_SERVER_ZIP $EXTRACTED_FILE_HTTP_SERVER_ZIP
ENV EXTRACTED_FILE_HTTP_SERVER_KEY $EXTRACTED_FILE_HTTP_SERVER_KEY
ENV EXTRACTED_FILE_HTTP_SERVER_RECURSIVE $EXTRACTED_FILE_HTTP_SERVER_RECURSIVE
ENV EXTRACTED_FILE_HTTP_SERVER_PORT $EXTRACTED_FILE_HTTP_SERVER_PORT

ENV EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE $EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE
ENV EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT $EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT
ENV EXTRACTED_FILE_PRUNE_INTERVAL_SECONDS $EXTRACTED_FILE_PRUNE_INTERVAL_SECONDS

################################################################################
ADD filescan/python-filescan/ /install-filescan/
ADD nginx/landingpage/css "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}/css"
ADD nginx/landingpage/js "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}/js"
ADD --chmod=644 docs/images/logo/Malcolm_background.png "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}/assets/img/bg-masthead.png"
ADD --chmod=644 docs/images/icon/favicon.ico "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}/favicon.ico"
ADD --chmod=755 shared/bin/web-ui-asset-download.sh /usr/local/bin/

RUN set -e ; \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} ; \
        useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} ; \
        usermod -a -G tty ${PUSER} ; \
    # fix our package lists, upgrade, and install a few minimal dependencies
    sed -i /etc/apt/sources.list.d/debian.sources -e 's/main$/main contrib non-free/' ; \
    apt-get update -q ; \
    apt-get upgrade -y -q --no-install-recommends ; \
    apt-get install -y -q --no-install-recommends \
      automake \
      build-essential \
      bash \
      bc \
      ca-certificates \
      curl \
      gcc \
      g++ \
      git \
      inotify-tools \
      jq \
      libjansson-dev \
      libjansson4 \
      libmagic-dev \
      libmagic1 \
      libssl-dev \
      libssl3 \
      libtool \
      make \
      openssl \
      pkg-config \
      psmisc \
      rsync \
      tini \
      unzip \
      webfs ; \
    curl -fsSL -o /usr/local/bin/supercronic "${SUPERCRONIC_URL}$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')" ; \
        chmod +x /usr/local/bin/supercronic ; \
    curl -fsSL -o /usr/local/bin/yq "${YQ_URL}$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')" ; \
        chmod 755 /usr/local/bin/yq ; \
    mkdir -p /filescan /filescan/data/files /filescan/data/logs "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}" ; \
    cd /tmp && \
      /usr/local/bin/web-ui-asset-download.sh -o "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}/css" && \
    cd /install-filescan ; \
        python3 -m pip install --break-system-packages --no-cache-dir -r requirements.txt ; \
        make ; \
        python3 -m pip install --break-system-packages --no-cache-dir . ; \
    cd /filescan ; \
    find /filescan "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}" -type d -exec chmod 755 "{}" \; ; \
    find /filescan "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}" -type f -exec chmod 644 "{}" \; ; \
    chown -R $PUSER:$PGROUP /filescan/data "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}" ; \
    apt-get remove -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge \
      automake \
      build-essential \
      gcc \
      g++ \
      gcc-12 \
      libc6-dev \
      libgcc-12-dev \
      libjansson-dev \
      libmagic-dev \
      libssl-dev \
      libtool \
      make ; \
    apt-get autoremove -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages ; \
        apt-get clean -y -q ; \
        rm -rf /install-filescan /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/* /usr/lib/x86_64-linux-gnu/*.a

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 container-health-scripts/filescan.sh /usr/local/bin/container_health.sh
ADD --chmod=755 filescan/docker-entrypoint.sh /docker-entrypoint.sh
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/prune_files.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=644 filescan/filescan-config.yml /filescan/filescan-config.yml
ADD --chmod=644 filescan/supervisord.conf /etc/supervisord.conf
ADD --chmod=755 shared/bin/extracted_files_http_server.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_constants.py /usr/local/bin/
ADD --chmod=644 shared/bin/watch_common.py /usr/local/bin/

################################################################################

VOLUME ["/filescan/data"]

EXPOSE $EXTRACTED_FILE_HTTP_SERVER_PORT
EXPOSE $FILESCAN_HEALTH_PORT

WORKDIR /filescan

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "filescan", \
            "/docker-entrypoint.sh"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]

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
