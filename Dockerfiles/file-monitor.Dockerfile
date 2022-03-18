FROM debian:11-slim

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/file-monitor'
LABEL org.opencontainers.image.description='Malcolm container for scanning files extracted by Zeek'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "monitor"
ENV PGROUP "monitor"
ENV PUSER_PRIV_DROP true

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ARG ZEEK_EXTRACTOR_PATH=/data/zeek/extract_files
ARG ZEEK_LOG_DIRECTORY=/data/zeek/logs
ARG EXTRACTED_FILE_IGNORE_EXISTING=false
ARG EXTRACTED_FILE_PRESERVATION=quarantined
ARG EXTRACTED_FILE_WATCHER_START_SLEEP=30
ARG EXTRACTED_FILE_SCANNER_START_SLEEP=10
ARG EXTRACTED_FILE_LOGGER_START_SLEEP=5
ARG EXTRACTED_FILE_MIN_BYTES=64
ARG EXTRACTED_FILE_MAX_BYTES=134217728
ARG VTOT_API2_KEY=0
ARG VTOT_REQUESTS_PER_MINUTE=4
ARG MALASS_HOST=0
ARG MALASS_PORT=80
ARG MALASS_MAX_REQUESTS=20
ARG EXTRACTED_FILE_ENABLE_CLAMAV=false
ARG EXTRACTED_FILE_UPDATE_RULES=false
ARG EXTRACTED_FILE_PIPELINE_DEBUG=false
ARG EXTRACTED_FILE_PIPELINE_DEBUG_EXTRA=false
ARG CLAMD_SOCKET_FILE=/tmp/clamd.ctl
ARG CLAMD_MAX_REQUESTS=8
ARG YARA_MAX_REQUESTS=8
ARG CAPA_MAX_REQUESTS=4
ARG EXTRACTED_FILE_ENABLE_YARA=false
ARG EXTRACTED_FILE_YARA_CUSTOM_ONLY=false
ARG EXTRACTED_FILE_ENABLE_CAPA=false
ARG EXTRACTED_FILE_CAPA_VERBOSE=false
ARG EXTRACTED_FILE_HTTP_SERVER_DEBUG=false
ARG EXTRACTED_FILE_HTTP_SERVER_ENABLE=false
ARG EXTRACTED_FILE_HTTP_SERVER_ENCRYPT=false
ARG EXTRACTED_FILE_HTTP_SERVER_KEY=quarantined
ARG EXTRACTED_FILE_HTTP_SERVER_PORT=8440

ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH
ENV ZEEK_LOG_DIRECTORY $ZEEK_LOG_DIRECTORY
ENV EXTRACTED_FILE_IGNORE_EXISTING $EXTRACTED_FILE_IGNORE_EXISTING
ENV EXTRACTED_FILE_PRESERVATION $EXTRACTED_FILE_PRESERVATION
ENV EXTRACTED_FILE_WATCHER_START_SLEEP $EXTRACTED_FILE_WATCHER_START_SLEEP
ENV EXTRACTED_FILE_SCANNER_START_SLEEP $EXTRACTED_FILE_SCANNER_START_SLEEP
ENV EXTRACTED_FILE_LOGGER_START_SLEEP $EXTRACTED_FILE_LOGGER_START_SLEEP
ENV EXTRACTED_FILE_MIN_BYTES $EXTRACTED_FILE_MIN_BYTES
ENV EXTRACTED_FILE_MAX_BYTES $EXTRACTED_FILE_MAX_BYTES
ENV VTOT_API2_KEY $VTOT_API2_KEY
ENV VTOT_REQUESTS_PER_MINUTE $VTOT_REQUESTS_PER_MINUTE
ENV MALASS_HOST $MALASS_HOST
ENV MALASS_PORT $MALASS_PORT
ENV MALASS_MAX_REQUESTS $MALASS_MAX_REQUESTS
ENV EXTRACTED_FILE_ENABLE_CLAMAV $EXTRACTED_FILE_ENABLE_CLAMAV
ENV EXTRACTED_FILE_UPDATE_RULES $EXTRACTED_FILE_UPDATE_RULES
ENV EXTRACTED_FILE_PIPELINE_DEBUG $EXTRACTED_FILE_PIPELINE_DEBUG
ENV EXTRACTED_FILE_PIPELINE_DEBUG_EXTRA $EXTRACTED_FILE_PIPELINE_DEBUG_EXTRA
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
ENV YARA_VERSION "4.2.0"
ENV YARA_URL "https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz"
ENV YARA_RULES_URL "https://github.com/Neo23x0/signature-base"
ENV YARA_RULES_DIR "/yara-rules"
ENV YARA_RULES_SRC_DIR "$SRC_BASE_DIR/signature-base"
ENV CAPA_VERSION "3.2.0"
ENV CAPA_URL "https://github.com/fireeye/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-linux.zip"
ENV CAPA_DIR "/opt/capa"
ENV CAPA_BIN "${CAPA_DIR}/capa"
ENV EXTRACTED_FILE_HTTP_SERVER_DEBUG $EXTRACTED_FILE_HTTP_SERVER_DEBUG
ENV EXTRACTED_FILE_HTTP_SERVER_ENABLE $EXTRACTED_FILE_HTTP_SERVER_ENABLE
ENV EXTRACTED_FILE_HTTP_SERVER_ENCRYPT $EXTRACTED_FILE_HTTP_SERVER_ENCRYPT
ENV EXTRACTED_FILE_HTTP_SERVER_KEY $EXTRACTED_FILE_HTTP_SERVER_KEY
ENV EXTRACTED_FILE_HTTP_SERVER_PORT $EXTRACTED_FILE_HTTP_SERVER_PORT

ENV SUPERCRONIC_VERSION "0.1.12"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "048b95b48b708983effb2e5c935a1ef8483d9e3e"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

RUN sed -i "s/bullseye main/bullseye main contrib non-free/g" /etc/apt/sources.list && \
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
      libclamunrar9 \
      libjansson-dev \
      libjansson4 \
      libmagic-dev \
      libmagic1 \
      libssl-dev \
      libssl1.1 \
      libtool \
      make \
      pkg-config \
      unzip && \
    apt-get  -y -q install \
      inotify-tools \
      libzmq5 \
      psmisc \
      python3 \
      python3-bs4 \
      python3-dev \
      python3-pip \
      python3-pyinotify \
      python3-requests \
      python3-zmq && \
    pip3 install clamd supervisor yara-python python-magic psutil pycryptodome && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
      echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
      chmod +x "$SUPERCRONIC" && \
      mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
      ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic && \
    mkdir -p "${SRC_BASE_DIR}" && \
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
    cd /tmp && \
      git clone --depth 1 --single-branch "${YARA_RULES_URL}" "${YARA_RULES_SRC_DIR}" && \
      mkdir -p "${YARA_RULES_DIR}" && \
      ln -f -s -r "${YARA_RULES_SRC_DIR}"/yara/* "${YARA_RULES_SRC_DIR}"/vendor/yara/* "${YARA_RULES_DIR}"/ && \
    cd /tmp && \
      curl -fsSL -o ./capa.zip "${CAPA_URL}" && \
      unzip ./capa.zip && \
      chmod 755 ./capa && \
      mkdir -p "${CAPA_DIR}" && \
      mv ./capa "${CAPA_BIN}" && \
      rm -f ./capa.zip && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove \
        automake \
        build-essential \
        gcc \
        gcc-8 \
        libc6-dev \
        libgcc-8-dev \
        libjansson-dev \
        libmagic-dev \
        libssl-dev \
        libtool \
        make \
        python3-dev && \
      apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* && \
    mkdir -p /var/log/clamav "${CLAMAV_RULES_DIR}" && \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} && \
      useradd -m --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} && \
      usermod -a -G tty ${PUSER} && \
    chown -R ${PUSER}:${PGROUP} /var/log/clamav "${CLAMAV_RULES_DIR}" "${CAPA_DIR}" "${YARA_RULES_DIR}" "${YARA_RULES_SRC_DIR}" && \
    find /var/log/clamav "${CLAMAV_RULES_DIR}" "${CAPA_DIR}" "${YARA_RULES_DIR}" "${YARA_RULES_SRC_DIR}" -type d -exec chmod 750 "{}" \; && \
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
      ln -r -s /usr/local/bin/zeek_carve_scanner.py /usr/local/bin/malass_scan.py && \
      echo "0 */6 * * * /bin/bash /usr/local/bin/capa-update.sh\n0 */6 * * * /bin/bash /usr/local/bin/yara-rules-update.sh" > ${SUPERCRONIC_CRONTAB}

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/zeek_carve*.py /usr/local/bin/
ADD shared/bin/malass_client.py /usr/local/bin/
ADD file-monitor/supervisord.conf /etc/supervisord.conf
ADD file-monitor/docker-entrypoint.sh /docker-entrypoint.sh
ADD file-monitor/*update.sh /usr/local/bin/

USER ${PUSER}

RUN /usr/bin/freshclam freshclam --config-file=/etc/clamav/freshclam.conf

USER root

WORKDIR /data/zeek/extract_files

ENV PATH "${CAPA_DIR}:${PATH}"

VOLUME ["$CAPA_DIR"]
VOLUME ["$CLAMAV_RULES_DIR"]
VOLUME ["$YARA_RULES_DIR"]
VOLUME ["$YARA_RULES_SRC_DIR"]

EXPOSE 3310
EXPOSE $EXTRACTED_FILE_HTTP_SERVER_PORT

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh", "/docker-entrypoint.sh"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
