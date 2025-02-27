FROM redis:7-alpine

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
LABEL org.opencontainers.image.title='ghcr.io/cisagov/malcolm/redis'
LABEL org.opencontainers.image.description='Malcolm container providing Redis, an in-memory data structure store'

ARG DEFAULT_UID=999
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "redis"
ENV PGROUP "redis"
ENV PUSER_PRIV_DROP true
USER root

ENV TERM xterm

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/redis.sh /usr/local/bin/container_health.sh

RUN apk update --no-cache && \
    apk upgrade --no-cache && \
    apk --no-cache add bash jq psmisc rsync shadow tini && \
    addgroup ${PUSER} tty

WORKDIR /home/${PUSER}

ENTRYPOINT ["/sbin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "redis"]

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
