FROM debian:13-slim

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/file-monitor'
LABEL org.opencontainers.image.description='Malcolm container for scanning files extracted by Zeek'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "monitor"
ENV PGROUP "monitor"
ENV PUSER_PRIV_DROP true
# see PUSER_CHOWN at the bottom of the file (after the other environment variables it references)
USER root

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ARG ZEEK_EXTRACTOR_PATH=/zeek/extract_files
ARG ZEEK_LOG_DIRECTORY=/zeek/logs
ARG EXTRACTED_FILE_IGNORE_EXISTING=false
ARG EXTRACTED_FILE_PRESERVATION=quarantined
ARG EXTRACTED_FILE_WATCHER_START_SLEEP=30
ARG EXTRACTED_FILE_WATCHER_POLLING=false
ARG EXTRACTED_FILE_WATCHER_POLLING_ASSUME_CLOSED_SEC=10
ARG EXTRACTED_FILE_SCANNER_START_SLEEP=10
ARG EXTRACTED_FILE_LOGGER_START_SLEEP=5
ARG EXTRACTED_FILE_MIN_BYTES=64
ARG EXTRACTED_FILE_MAX_BYTES=134217728
ARG EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE=1TB
ARG EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT=0
ARG EXTRACTED_FILE_PRUNE_INTERVAL_SECONDS=300
ARG VTOT_API2_KEY=0
ARG VTOT_REQUESTS_PER_MINUTE=4
ARG EXTRACTED_FILE_ENABLE_CLAMAV=false
ARG EXTRACTED_FILE_UPDATE_RULES=false
ARG EXTRACTED_FILE_PIPELINE_VERBOSITY=""
ARG CLAMD_SOCKET_FILE=/tmp/clamd.ctl
ARG CLAMD_MAX_REQUESTS=8
ARG YARA_MAX_REQUESTS=8
ARG CAPA_MAX_REQUESTS=4
ARG EXTRACTED_FILE_ENABLE_YARA=false
ARG EXTRACTED_FILE_YARA_CUSTOM_ONLY=false
ARG EXTRACTED_FILE_ENABLE_CAPA=false
ARG EXTRACTED_FILE_CAPA_VERBOSE=false
ARG EXTRACTED_FILE_HTTP_SERVER_ENABLE=false
ARG EXTRACTED_FILE_HTTP_SERVER_ZIP=true
ARG EXTRACTED_FILE_HTTP_SERVER_KEY=infected
ARG EXTRACTED_FILE_HTTP_SERVER_RECURSIVE=true
ARG EXTRACTED_FILE_HTTP_SERVER_PORT=8006

ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH
ENV ZEEK_LOG_DIRECTORY $ZEEK_LOG_DIRECTORY
ENV EXTRACTED_FILE_IGNORE_EXISTING $EXTRACTED_FILE_IGNORE_EXISTING
ENV EXTRACTED_FILE_PRESERVATION $EXTRACTED_FILE_PRESERVATION
ENV EXTRACTED_FILE_WATCHER_START_SLEEP $EXTRACTED_FILE_WATCHER_START_SLEEP
ENV EXTRACTED_FILE_WATCHER_POLLING $EXTRACTED_FILE_WATCHER_POLLING
ENV EXTRACTED_FILE_WATCHER_POLLING_ASSUME_CLOSED_SEC $EXTRACTED_FILE_WATCHER_POLLING_ASSUME_CLOSED_SEC
ENV EXTRACTED_FILE_SCANNER_START_SLEEP $EXTRACTED_FILE_SCANNER_START_SLEEP
ENV EXTRACTED_FILE_LOGGER_START_SLEEP $EXTRACTED_FILE_LOGGER_START_SLEEP
ENV EXTRACTED_FILE_MIN_BYTES $EXTRACTED_FILE_MIN_BYTES
ENV EXTRACTED_FILE_MAX_BYTES $EXTRACTED_FILE_MAX_BYTES
ENV EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE $EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE
ENV EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT $EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT
ENV EXTRACTED_FILE_PRUNE_INTERVAL_SECONDS $EXTRACTED_FILE_PRUNE_INTERVAL_SECONDS
ENV VTOT_API2_KEY $VTOT_API2_KEY
ENV VTOT_REQUESTS_PER_MINUTE $VTOT_REQUESTS_PER_MINUTE
ENV EXTRACTED_FILE_ENABLE_CLAMAV $EXTRACTED_FILE_ENABLE_CLAMAV
ENV EXTRACTED_FILE_UPDATE_RULES $EXTRACTED_FILE_UPDATE_RULES
ENV EXTRACTED_FILE_PIPELINE_VERBOSITY $EXTRACTED_FILE_PIPELINE_VERBOSITY
ENV CLAMD_SOCKET_FILE $CLAMD_SOCKET_FILE
ENV CLAMD_MAX_REQUESTS $CLAMD_MAX_REQUESTS
ENV YARA_MAX_REQUESTS $YARA_MAX_REQUESTS
ENV CAPA_MAX_REQUESTS $CAPA_MAX_REQUESTS
ENV EXTRACTED_FILE_ENABLE_YARA $EXTRACTED_FILE_ENABLE_YARA
ENV EXTRACTED_FILE_YARA_CUSTOM_ONLY $EXTRACTED_FILE_YARA_CUSTOM_ONLY
ENV EXTRACTED_FILE_ENABLE_CAPA $EXTRACTED_FILE_ENABLE_CAPA
ENV EXTRACTED_FILE_CAPA_VERBOSE $EXTRACTED_FILE_CAPA_VERBOSE
ENV SRC_BASE_DIR "/usr/local/src"
ENV CLAMAV_RULES_DIR "/var/lib/clamav"
ENV YARA_VERSION "4.5.3"
ENV YARA_URL "https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz"
ENV YARA_RULES_SRC_DIR "/yara-rules-src"
ENV YARA_RULES_DIR "/yara-rules"
ENV EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR "/opt/assets"
ENV EXTRACTED_FILE_HTTP_SERVER_ENABLE $EXTRACTED_FILE_HTTP_SERVER_ENABLE
ENV EXTRACTED_FILE_HTTP_SERVER_ZIP $EXTRACTED_FILE_HTTP_SERVER_ZIP
ENV EXTRACTED_FILE_HTTP_SERVER_KEY $EXTRACTED_FILE_HTTP_SERVER_KEY
ENV EXTRACTED_FILE_HTTP_SERVER_RECURSIVE $EXTRACTED_FILE_HTTP_SERVER_RECURSIVE
ENV EXTRACTED_FILE_HTTP_SERVER_PORT $EXTRACTED_FILE_HTTP_SERVER_PORT

ENV SUPERCRONIC_VERSION "0.2.39"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ADD --chmod=755 shared/bin/yara_rules_setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/capa-build.sh /usr/local/bin/
ADD nginx/landingpage/css "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}/css"
ADD nginx/landingpage/js "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}/js"
ADD --chmod=644 docs/images/logo/Malcolm_background.png "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}/assets/img/bg-masthead.png"
ADD --chmod=644 docs/images/icon/favicon.ico "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}/favicon.ico"
ADD --chmod=755 shared/bin/web-ui-asset-download.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/file-monitor.sh /usr/local/bin/container_health.sh
ADD --chmod=644 file-monitor/requirements.txt /usr/local/src/

RUN export BINARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    sed -i "s/main$/main contrib non-free/g" /etc/apt/sources.list.d/debian.sources && \
    apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install --no-install-recommends -y -q \
      automake \
      bc \
      clamav \
      clamav-daemon \
      clamav-freshclam \
      curl \
      gcc \
      git \
      jq \
      libclamunrar12 \
      libjansson-dev \
      libjansson4 \
      libmagic-dev \
      libmagic1 \
      libssl-dev \
      libssl3 \
      libtool \
      make \
      pkg-config \
      tini \
      unzip && \
    apt-get -y -q install \
      inotify-tools \
      libzmq5 \
      psmisc \
      python3 \
      python3-venv \
      python3-bs4 \
      python3-dev \
      python3-pip \
      python3-requests \
      python3-zmq \
      rsync && \
    python3 -m pip install --break-system-packages --no-compile --no-cache-dir -r /usr/local/src/requirements.txt && \
    curl -fsSL -o /usr/local/bin/supercronic "${SUPERCRONIC_URL}${BINARCH}" && \
      chmod +x /usr/local/bin/supercronic && \
    mkdir -p "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}" "${SRC_BASE_DIR}" "${YARA_RULES_DIR}" "${YARA_RULES_SRC_DIR}" && \
    cd "${SRC_BASE_DIR}" && \
      curl -sSL "${YARA_URL}" | tar xzf - -C "${SRC_BASE_DIR}" && \
      cd "./yara-${YARA_VERSION}" && \
        ./bootstrap.sh && \
        ./configure --prefix=/usr \
          --with-crypto \
          --enable-magic \
          --enable-cuckoo \
          --enable-dotnet && \
        make && \
        make install && \
      rm -rf "${SRC_BASE_DIR}"/yara* && \
    cd "${YARA_RULES_SRC_DIR}" && \
      /usr/local/bin/yara_rules_setup.sh -r "${YARA_RULES_SRC_DIR}" -y "${YARA_RULES_DIR}" && \
    cd /tmp && \
      /usr/local/bin/web-ui-asset-download.sh -o "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}/css" && \
    cd /tmp && \
      /usr/local/bin/capa-build.sh && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove \
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
        python3-venv && \
    mkdir -p /var/log/clamav "${CLAMAV_RULES_DIR}" && \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} && \
      useradd -m --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} && \
      usermod -a -G tty ${PUSER} && \
    chown -R ${PUSER}:${PGROUP} /var/log/clamav "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}" "${CLAMAV_RULES_DIR}" "${YARA_RULES_DIR}" "${YARA_RULES_SRC_DIR}" && \
    find /var/log/clamav "${EXTRACTED_FILE_HTTP_SERVER_ASSETS_DIR}" "${CLAMAV_RULES_DIR}" "${YARA_RULES_DIR}" "${YARA_RULES_SRC_DIR}" -type d -exec chmod 750 "{}" \; && \
    sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf && \
      sed -i "s/^User .*$/User ${PUSER}/g" /etc/clamav/clamd.conf && \
      sed -i "s|^LocalSocket .*$|LocalSocket $CLAMD_SOCKET_FILE|g" /etc/clamav/clamd.conf && \
      sed -i "s/^LocalSocketGroup .*$/LocalSocketGroup ${PGROUP}/g" /etc/clamav/clamd.conf && \
      sed -i "s/^MaxFileSize .*$/MaxFileSize $EXTRACTED_FILE_MAX_BYTES/g" /etc/clamav/clamd.conf && \
      sed -i "s/^MaxScanSize .*$/MaxScanSize $(echo "$EXTRACTED_FILE_MAX_BYTES * 4" | bc)/g" /etc/clamav/clamd.conf && \
      echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    if ! [ -z $HTTPProxyServer ]; then echo "HTTPProxyServer $HTTPProxyServer" >> /etc/clamav/freshclam.conf; fi && \
      if ! [ -z $HTTPProxyPort   ]; then echo "HTTPProxyPort $HTTPProxyPort" >> /etc/clamav/freshclam.conf; fi && \
      sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/freshclam.conf && \
      sed -i "s/^DatabaseOwner .*$/DatabaseOwner ${PUSER}/g" /etc/clamav/freshclam.conf && \
      ln -r -s /usr/local/bin/zeek_carve_scanner.py /usr/local/bin/vtot_scan.py && \
      ln -r -s /usr/local/bin/zeek_carve_scanner.py /usr/local/bin/clam_scan.py && \
      ln -r -s /usr/local/bin/zeek_carve_scanner.py /usr/local/bin/yara_scan.py && \
      ln -r -s /usr/local/bin/zeek_carve_scanner.py /usr/local/bin/capa_scan.py && \
      echo "0 */6 * * * /usr/local/bin/yara_rules_setup.sh -r \"${YARA_RULES_SRC_DIR}\" -y \"${YARA_RULES_DIR}\"" > ${SUPERCRONIC_CRONTAB} && \
  apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* /tmp/*

USER ${PUSER}

RUN /usr/bin/freshclam freshclam --config-file=/etc/clamav/freshclam.conf

USER root

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/prune_files.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 shared/bin/zeek_carve*.py /usr/local/bin/
ADD --chmod=755 shared/bin/extracted_files_http_server.py /usr/local/bin/
ADD --chmod=644 shared/bin/watch_common.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_constants.py /usr/local/bin/
ADD --chmod=644 file-monitor/supervisord.conf /etc/supervisord.conf
ADD --chmod=755 file-monitor/docker-entrypoint.sh /docker-entrypoint.sh

WORKDIR /zeek/extract_files

# This is to handle an issue when running with rootless podman and
#   "userns_mode: keep-id". It seems that anything defined as a VOLUME
#   in the Dockerfile is getting set with an ownership of 999:999.
#   This is to override that, although I'm not yet sure if there are
#   other implications. See containers/podman#23347.
ENV PUSER_CHOWN "$CLAMAV_RULES_DIR;$YARA_RULES_DIR;$YARA_RULES_SRC_DIR"

# see PUSER_CHOWN comment above
VOLUME ["$CLAMAV_RULES_DIR"]
VOLUME ["$YARA_RULES_DIR"]
VOLUME ["$YARA_RULES_SRC_DIR"]

EXPOSE 3310
EXPOSE $EXTRACTED_FILE_HTTP_SERVER_PORT

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "file-monitor", \
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
