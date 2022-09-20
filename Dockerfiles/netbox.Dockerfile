FROM netboxcommunity/netbox:latest

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/netbox'
LABEL org.opencontainers.image.description='Malcolm container providing the NetBox asset management system'

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV LANG C.UTF-8

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "boxer"
ENV PGROUP "boxer"
ENV PUSER_PRIV_DROP true

ARG BASE_PATH=assets
ENV BASE_PATH $BASE_PATH

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
      procps \
      psmisc \
      python3-psycopg2 \
      python3-pynetbox \
      python3-slugify \
      supervisor \
      tini && \
    apt-get -q -y autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    groupadd --gid ${DEFAULT_GID} ${PUSER} && \
    useradd -m --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} && \
    usermod -a -G tty ${PUSER} && \
    mkdir -p /opt/unit /etc/supervisor.d && \
    chown -R $PUSER:$PGROUP /etc/netbox /opt/unit /opt/netbox && \
    if [ -n "${BASE_PATH}" ] && [ "${BASE_PATH}" != "netbox" ]; then \
        mkdir /opt/netbox/netbox/$BASE_PATH && \
        mv /opt/netbox/netbox/static /opt/netbox/netbox/$BASE_PATH/static; \
    fi

COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=755 netbox/scripts/* /usr/local/bin/
COPY --chmod=644 netbox/supervisord.conf /etc/supervisord.conf

ENTRYPOINT [ "/usr/bin/tini", "--", "/usr/local/bin/docker-uid-gid-setup.sh" ]

CMD ["/opt/netbox/docker-entrypoint.sh", "/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]

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
