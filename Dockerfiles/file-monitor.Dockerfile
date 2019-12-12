FROM debian:buster-slim

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/file-monitor'
LABEL org.opencontainers.image.description='Malcolm container for scanning files extracted by Zeek'


ENV DEBIAN_FRONTEND noninteractive

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

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
    apt-get update && \
    apt-get install --no-install-recommends -y -q \
      bc \
      clamav \
      clamav-daemon \
      clamav-freshclam \
      libclamunrar9 \
      wget && \
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
    pip3 install clamd supervisor && \
    mkdir -p /var/log/supervisor && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove python3-dev build-essential && \
      apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* && \
    wget -O /var/lib/clamav/main.cvd http://database.clamav.net/main.cvd && \
      wget -O /var/lib/clamav/daily.cvd http://database.clamav.net/daily.cvd && \
      wget -O /var/lib/clamav/bytecode.cvd http://database.clamav.net/bytecode.cvd && \
    groupadd --gid 1000 monitor && \
      useradd -M --uid 1000 --gid 1000 monitor && \
    mkdir -p /var/log/clamav /var/lib/clamav && \
      chown -R monitor:monitor /var/log/clamav  /var/lib/clamav && \
      chmod -R 750 /var/log/clamav  /var/lib/clamav && \
    sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf && \
      sed -i 's/^User .*$/User monitor/g' /etc/clamav/clamd.conf && \
      sed -i "s|^LocalSocket .*$|LocalSocket $CLAMD_SOCKET_FILE|g" /etc/clamav/clamd.conf && \
      sed -i 's/^LocalSocketGroup .*$/LocalSocketGroup monitor/g' /etc/clamav/clamd.conf && \
      sed -i "s/^MaxFileSize .*$/MaxFileSize $EXTRACTED_FILE_MAX_BYTES/g" /etc/clamav/clamd.conf && \
      sed -i "s/^MaxScanSize .*$/MaxScanSize $(echo "$EXTRACTED_FILE_MAX_BYTES * 4" | bc)/g" /etc/clamav/clamd.conf && \
      echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    if ! [ -z $HTTPProxyServer ]; then echo "HTTPProxyServer $HTTPProxyServer" >> /etc/clamav/freshclam.conf; fi && \
      if ! [ -z $HTTPProxyPort   ]; then echo "HTTPProxyPort $HTTPProxyPort" >> /etc/clamav/freshclam.conf; fi && \
      sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/freshclam.conf && \
      sed -i 's/^DatabaseOwner .*$/DatabaseOwner monitor/g' /etc/clamav/freshclam.conf

ADD shared/bin/zeek_carve_*.py /usr/local/bin/
ADD shared/bin/malass_client.py /usr/local/bin/
ADD file-monitor/supervisord.conf /etc/supervisord.conf

WORKDIR /data/zeek/extract_files

VOLUME ["/var/lib/clamav"]

EXPOSE 3310

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
