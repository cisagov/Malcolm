FROM debian:buster-slim

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
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
ARG EXTRACTED_FILE_ENABLE_FRESHCLAM=false
ARG EXTRACTED_FILE_PIPELINE_DEBUG=false
ARG EXTRACTED_FILE_PIPELINE_DEBUG_EXTRA=false
ARG CLAMD_SOCKET_FILE=/tmp/clamd.ctl
ARG EXTRACTED_FILE_ENABLE_YARA=false
ARG EXTRACTED_FILE_YARA_CUSTOM_ONLY=false
ARG EXTRACTED_FILE_ENABLE_CAPA=false
ARG EXTRACTED_FILE_CAPA_VERBOSE=false

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
ENV EXTRACTED_FILE_ENABLE_FRESHCLAM $EXTRACTED_FILE_ENABLE_FRESHCLAM
ENV EXTRACTED_FILE_PIPELINE_DEBUG $EXTRACTED_FILE_PIPELINE_DEBUG
ENV EXTRACTED_FILE_PIPELINE_DEBUG_EXTRA $EXTRACTED_FILE_PIPELINE_DEBUG_EXTRA
ENV CLAMD_SOCKET_FILE $CLAMD_SOCKET_FILE
ENV EXTRACTED_FILE_ENABLE_YARA $EXTRACTED_FILE_ENABLE_YARA
ENV EXTRACTED_FILE_YARA_CUSTOM_ONLY $EXTRACTED_FILE_YARA_CUSTOM_ONLY
ENV EXTRACTED_FILE_ENABLE_CAPA $EXTRACTED_FILE_ENABLE_CAPA
ENV EXTRACTED_FILE_CAPA_VERBOSE $EXTRACTED_FILE_CAPA_VERBOSE
ENV YARA_VERSION "4.0.2"
ENV YARA_URL "https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz"
ENV YARA_RULES_URL "https://codeload.github.com/Neo23x0/signature-base/tar.gz/master"
ENV YARA_RULES_DIR "/yara-rules"
ENV CAPA_URL "https://github.com/fireeye/capa"
ENV CAPA_RULES_DIR "/opt/capa-rules"
ENV SRC_BASE_DIR "/usr/local/src"

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
    apt-get update && \
    apt-get install --no-install-recommends -y -q \
      automake \
      bc \
      clamav \
      clamav-daemon \
      clamav-freshclam \
      curl \
      gcc \
      git \
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
      python \
      python-dev \
      python-pip \
      python-backports-shutil-get-terminal-size \
      python3 \
      python3-bs4 \
      python3-dev \
      python3-pip \
      python3-pyinotify \
      python3-requests \
      python3-zmq && \
    pip3 install clamd supervisor yara-python python-magic psutil && \
    pip2 install flare-capa && \
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
      mkdir -p ./Neo23x0 && \
      curl -sSL "$YARA_RULES_URL" | tar xzvf - -C ./Neo23x0 --strip-components 1 && \
      mkdir -p "${YARA_RULES_DIR}" && \
      cp ./Neo23x0/yara/* ./Neo23x0/vendor/yara/* "${YARA_RULES_DIR}"/ && \
      cp ./Neo23x0/LICENSE "${YARA_RULES_DIR}"/_LICENSE && \
      rm -rf /tmp/Neo23x0 && \
    cd /tmp && \
      git clone --depth 1 --single-branch --branch "v$(/usr/local/bin/capa --version 2>&1 | awk '{print $2}')" "${CAPA_URL}" /tmp/capa && \
      cd /tmp/capa && \
      git submodule init rules && \
      git submodule update --depth 1 rules && \
      cd /tmp && \
      rm -rf "${CAPA_RULES_DIR}" && \
      mv /tmp/capa/rules "${CAPA_RULES_DIR}" && \
      rm -rf "${CAPA_RULES_DIR}"/.git* /tmp/capa && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove \
        automake \
        build-essential \
        gcc \
        gcc-8 \
        git \
        libc6-dev \
        libgcc-8-dev \
        libjansson-dev \
        libmagic-dev \
        libssl-dev \
        libtool \
        make \
        python-dev \
        python3-dev \
        unzip && \
      apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* && \
    curl -s -S -L -o /var/lib/clamav/main.cvd http://database.clamav.net/main.cvd && \
      curl -s -S -L -o /var/lib/clamav/daily.cvd http://database.clamav.net/daily.cvd && \
      curl -s -S -L -o /var/lib/clamav/bytecode.cvd http://database.clamav.net/bytecode.cvd && \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} && \
      useradd -m --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} && \
      usermod -a -G tty ${PUSER} && \
    mkdir -p /var/log/clamav /var/lib/clamav && \
      chown -R ${PUSER}:${PGROUP} /var/log/clamav  /var/lib/clamav && \
      chmod -R 750 /var/log/clamav  /var/lib/clamav && \
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
      ln -r -s /usr/local/bin/zeek_carve_scanner.py /usr/local/bin/malass_scan.py

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/zeek_carve_*.py /usr/local/bin/
ADD shared/bin/malass_client.py /usr/local/bin/
ADD file-monitor/supervisord.conf /etc/supervisord.conf
ADD file-monitor/docker-entrypoint.sh /docker-entrypoint.sh

WORKDIR /data/zeek/extract_files

VOLUME ["/var/lib/clamav"]

EXPOSE 3310

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh", "/docker-entrypoint.sh"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
