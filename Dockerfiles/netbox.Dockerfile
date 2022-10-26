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

ENV SUPERCRONIC_VERSION "0.2.1"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "d7f4c0886eb85249ad05ed592902fa6865bb9d70"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ARG NETBOX_DEFAULT_SITE=Malcolm
ARG NETBOX_CRON=false

ENV BASE_PATH netbox
ENV NETBOX_DEFAULT_SITE $NETBOX_DEFAULT_SITE
ENV NETBOX_CRON $NETBOX_CRON

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
      jq \
      procps \
      psmisc \
      supervisor \
      tini && \
    /opt/netbox/venv/bin/python -m pip install psycopg2 pynetbox python-slugify && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
      echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
      chmod +x "$SUPERCRONIC" && \
      mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
      ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic && \
      touch "${SUPERCRONIC_CRONTAB}" && \
    apt-get -q -y autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    groupadd --gid ${DEFAULT_GID} ${PUSER} && \
    useradd -m --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} && \
    usermod -a -G tty ${PUSER} && \
    mkdir -p /opt/unit && \
    chown -R $PUSER:$PGROUP /etc/netbox /opt/unit /opt/netbox && \
    mkdir -p /opt/netbox/netbox/$BASE_PATH && \
      mv /opt/netbox/netbox/static /opt/netbox/netbox/$BASE_PATH/static && \
      jq '. += { "settings": { "http": { "discard_unsafe_fields": false } } }' /etc/unit/nginx-unit.json | jq ".routes[0].match.uri = \"/${BASE_PATH}/static/*\"" > /etc/unit/nginx-unit-new.json && \
      mv /etc/unit/nginx-unit-new.json /etc/unit/nginx-unit.json && \
      chmod 644 /etc/unit/nginx-unit.json

COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
COPY --chmod=755 netbox/scripts/* /usr/local/bin/
COPY --chmod=644 netbox/supervisord.conf /etc/supervisord.conf
COPY --from=pierrezemb/gostatic --chmod=755 /goStatic /usr/bin/goStatic

EXPOSE 9001

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-uid-gid-setup.sh", "/usr/local/bin/service_check_passthrough.sh"]

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
