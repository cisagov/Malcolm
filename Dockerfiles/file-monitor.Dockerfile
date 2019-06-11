FROM debian:buster-slim AS build

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"

ENV DEBIAN_FRONTEND noninteractive

ARG ZEEK_EXTRACTOR_PATH=/data/zeek/extract_files
ARG ZEEK_LOG_DIRECTORY=/data/zeek/logs
ARG EXTRACTED_FILE_IGNORE_EXISTING=false
ARG EXTRACTED_FILE_PRESERVATION=quarantined
ARG EXTRACTED_FILE_START_SLEEP=30
ARG EXTRACTED_FILE_MIN_BYTES=64
ARG EXTRACTED_FILE_MAX_BYTES=134217728
ARG VTOT_API2_KEY=0
ARG VTOT_REQUESTS_PER_MINUTE=4
ARG MALASS_HOST=0
ARG MALASS_PORT=80
ARG MALASS_MAX_REQUESTS=20
ARG EXTRACTED_FILE_ENABLE_CLAMAV=false
ARG EXTRACTED_FILE_ENABLE_FRESHCLAM=false
ARG EXTRACTED_FILE_VERBOSE=false

ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH
ENV ZEEK_LOG_DIRECTORY $ZEEK_LOG_DIRECTORY
ENV EXTRACTED_FILE_IGNORE_EXISTING $EXTRACTED_FILE_IGNORE_EXISTING
ENV EXTRACTED_FILE_PRESERVATION $EXTRACTED_FILE_PRESERVATION
ENV EXTRACTED_FILE_START_SLEEP $EXTRACTED_FILE_START_SLEEP
ENV EXTRACTED_FILE_MIN_BYTES $EXTRACTED_FILE_MIN_BYTES
ENV EXTRACTED_FILE_MAX_BYTES $EXTRACTED_FILE_MAX_BYTES
ENV VTOT_API2_KEY $VTOT_API2_KEY
ENV VTOT_REQUESTS_PER_MINUTE $VTOT_REQUESTS_PER_MINUTE
ENV MALASS_HOST $MALASS_HOST
ENV MALASS_PORT $MALASS_PORT
ENV MALASS_MAX_REQUESTS $MALASS_MAX_REQUESTS
ENV EXTRACTED_FILE_ENABLE_CLAMAV $EXTRACTED_FILE_ENABLE_CLAMAV
ENV EXTRACTED_FILE_ENABLE_FRESHCLAM $EXTRACTED_FILE_ENABLE_FRESHCLAM
ENV EXTRACTED_FILE_VERBOSE $EXTRACTED_FILE_VERBOSE

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
      psmisc \
      python3 \
      python3-bs4 \
      python3-cachetools \
      python3-dev \
      python3-pip \
      python3-pyinotify \
      python3-requests && \
    pip3 install clamd namedlist supervisor && \
    mkdir -p /var/log/supervisor && \
    apt-get -y -q --force-yes --purge remove python3-dev build-essential && \
      apt-get -y -q --force-yes autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* && \
    wget -O /var/lib/clamav/main.cvd http://database.clamav.net/main.cvd && \
      wget -O /var/lib/clamav/daily.cvd http://database.clamav.net/daily.cvd && \
      wget -O /var/lib/clamav/bytecode.cvd http://database.clamav.net/bytecode.cvd && \
    groupadd --gid 1000 monitor && \
      useradd -M --uid 1000 --gid 1000 monitor && \
    mkdir -p /var/run/clamav /var/log/clamav /var/lib/clamav && \
      chown -R monitor:monitor /var/run/clamav /var/log/clamav  /var/lib/clamav && \
      chmod -R 750 /var/run/clamav /var/log/clamav  /var/lib/clamav && \
    sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf && \
      sed -i 's/^User .*$/User monitor/g' /etc/clamav/clamd.conf && \
      sed -i 's/^LocalSocketGroup .*$/LocalSocketGroup monitor/g' /etc/clamav/clamd.conf && \
      sed -i "s/^MaxFileSize .*$/MaxFileSize $EXTRACTED_FILE_MAX_BYTES/g" /etc/clamav/clamd.conf && \
      sed -i "s/^MaxScanSize .*$/MaxScanSize $(echo "$EXTRACTED_FILE_MAX_BYTES * 4" | bc)/g" /etc/clamav/clamd.conf && \
      echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    if ! [ -z $HTTPProxyServer ]; then echo "HTTPProxyServer $HTTPProxyServer" >> /etc/clamav/freshclam.conf; fi && \
      if ! [ -z $HTTPProxyPort   ]; then echo "HTTPProxyPort $HTTPProxyPort" >> /etc/clamav/freshclam.conf; fi && \
      sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/freshclam.conf && \
      sed -i 's/^DatabaseOwner .*$/DatabaseOwner monitor/g' /etc/clamav/freshclam.conf

ADD shared/bin/zeek-carve-monitor.py /usr/local/bin
ADD shared/bin/malass_client.py /usr/local/bin
ADD shared/bin/carveutils.py /usr/local/bin
ADD file-monitor/supervisord.conf /etc/supervisord.conf

WORKDIR /data/zeek/extract_files

VOLUME ["/var/lib/clamav"]

EXPOSE 3310

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]
