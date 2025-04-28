FROM debian:12-slim

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
LABEL org.opencontainers.image.title='ghcr.io/cisagov/malcolm/freq'
LABEL org.opencontainers.image.description='Malcolm container providing an interface to Mark Baggett''s freq_server.py'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "freq"
ENV PGROUP "freq"
ENV PUSER_PRIV_DROP true
USER root

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ARG FREQ_API_PORT=10004
ARG FREQ_LOOKUP=true

ENV FREQ_API_PORT $FREQ_API_PORT
ENV FREQ_LOOKUP   $FREQ_LOOKUP

ENV FREQ_URL "https://codeload.github.com/markbaggett/freq/tar.gz/master"

ADD --chmod=644 freq-server/requirements.txt /usr/local/src/

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install \
      curl \
      jq \
      procps \
      psmisc \
      python3 \
      python3-dev \
      python3-pip \
      rsync \
      tini && \
    pip3 install --break-system-packages --no-compile --no-cache-dir -r /usr/local/src/requirements.txt && \
    cd /opt && \
    mkdir -p ./freq_server && \
      curl -sSL "$FREQ_URL" | tar xzvf - -C ./freq_server --strip-components 1 && \
      rm -rf /opt/freq_server/systemd /opt/freq_server/upstart /opt/freq_server/*.md /opt/freq_server/*.exe && \
      mv -v "$(ls /opt/freq_server/*.freq | tail -n 1)" /opt/freq_server/freq_table.freq && \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} && \
      useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} && \
      chown -R ${PUSER}:${PGROUP} /opt/freq_server && \
      usermod -a -G tty ${PUSER} && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove git python3-dev build-essential && \
      apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/freq.sh /usr/local/bin/container_health.sh
ADD --chmod=644 freq-server/supervisord.conf /etc/supervisord.conf

WORKDIR /opt/freq_server

EXPOSE $FREQ_API_PORT

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "freq"]

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
