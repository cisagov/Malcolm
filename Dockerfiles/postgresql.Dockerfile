FROM postgres:16-alpine

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
LABEL org.opencontainers.image.title='ghcr.io/cisagov/malcolm/postgresql'
LABEL org.opencontainers.image.description='Malcolm container providing the PostgreSQL object-relational database'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "postgres"
ENV PGROUP "postgres"
ENV PUSER_PRIV_DROP true
ENV PUSER_CHOWN "/run/postgresql;/var/lib/postgresql"
USER root

ENV TERM xterm

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/postgres.sh /usr/local/bin/container_health.sh
ADD --chmod=755 postgres-scripts/docker-entrypoint-initdb.d/*.sh /docker-entrypoint-initdb.d/
ADD --chmod=755 postgres-scripts/docker-entrypoint-startdb.d/*.sh /docker-entrypoint-startdb.d/
ADD --chmod=755 postgres-scripts/*.sh /usr/local/bin/

RUN apk update --no-cache && \
    apk upgrade --no-cache && \
    apk add --no-cache bash jq procps psmisc rsync shadow tini && \
    apk add --no-cache --virtual .build-deps rsync && \
    rsync -a /usr/local/bin/ /usr/bin/ && \
    rsync -a /usr/local/share/ /usr/share/ && \
    rsync -a /usr/local/lib/ /usr/lib/ && \
    rm -rf /usr/local/bin /usr/local/share /usr/local/lib && \
    ln -s /usr/bin /usr/local/bin && \
    ln -s /usr/share /usr/local/share && \
    ln -s /usr/lib /usr/local/lib && \
    chmod 00775 /var/lib/postgresql /var/lib/postgresql/data /run/postgresql && \
    apk del .build-deps

USER root

ENTRYPOINT ["/sbin/tini", \
            "--", \
            "/usr/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "postgres", \
            "/usr/bin/docker-entrypoint-startdb.sh"]

CMD ["/usr/bin/docker-entrypoint.sh", "postgres"]

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
