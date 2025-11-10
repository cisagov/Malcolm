FROM debian:13-slim

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/strelka-clamav'
LABEL org.opencontainers.image.description='Malcolm container providing for ClamAV support for Strelka'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "strclam"
ENV PGROUP "strclam"
ENV PUSER_PRIV_DROP true
USER root

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install \
        ca-certificates \
        clamav \
        clamav-daemon \
        clamav-freshclam \
        rsync \
        tini && \
    update-rc.d clamav-daemon remove && \
        update-rc.d clamav-freshclam remove && \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} && \
      useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} && \
      usermod -a -G tty ${PUSER} && \
    apt-get clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --chmod=644 ./strelka/build/other/clamav/freshclam.conf \
                    ./strelka/build/other/clamav/freshclam-clamd.conf \
                    ./strelka/build/other/clamav/clamd.conf \
                 /etc/clamav/
COPY --chmod=755 ./strelka/build/other/clamav/clamd-entrypoint.sh \
                    shared/bin/docker-uid-gid-setup.sh \
                    shared/bin/service_check_passthrough.sh \
                 /usr/local/bin/
COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "strelka-clamav"]

CMD ["/clamd-entrypoint.sh"]

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
