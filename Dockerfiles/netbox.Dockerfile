FROM netboxcommunity/netbox:v3.5.7

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/netbox'
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

ENV SUPERCRONIC_VERSION "0.2.26"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "7a79496cf8ad899b99a719355d4db27422396735"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ENV YQ_VERSION "4.33.3"
ENV YQ_URL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64"

ENV NETBOX_DEVICETYPE_LIBRARY_URL "https://codeload.github.com/netbox-community/devicetype-library/tar.gz/master"

ARG NETBOX_DEVICETYPE_LIBRARY_PATH="/opt/netbox-devicetype-library"
ARG NETBOX_DEFAULT_SITE=Malcolm
ARG NETBOX_CRON=true
ARG NETBOX_PRELOAD_PATH="/opt/netbox-preload"

ENV NETBOX_PATH /opt/netbox
ENV BASE_PATH netbox
ENV NETBOX_DEVICETYPE_LIBRARY_PATH $NETBOX_DEVICETYPE_LIBRARY_PATH
ENV NETBOX_DEFAULT_SITE $NETBOX_DEFAULT_SITE
ENV NETBOX_CRON $NETBOX_CRON
ENV NETBOX_PRELOAD_PATH $NETBOX_PRELOAD_PATH

ADD netbox/patch/* /tmp/netbox-patches/

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
      git \
      jq \
      patch \
      procps \
      psmisc \
      rsync \
      supervisor \
      tini && \
    "${NETBOX_PATH}/venv/bin/python" -m pip install --break-system-packages --no-cache-dir 'git+https://github.com/mmguero-dev/netbox-initializers' psycopg2 pynetbox python-slugify randomcolor && \
    cd "${NETBOX_PATH}" && \
      bash -c 'for i in /tmp/netbox-patches/*; do patch -p 1 -r - --no-backup-if-mismatch < $i || true; done' && \
    curl -fsSLO "${SUPERCRONIC_URL}" && \
      echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
      chmod +x "${SUPERCRONIC}" && \
      mv "${SUPERCRONIC}" "/usr/local/bin/${SUPERCRONIC}" && \
      ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic && \
      touch "${SUPERCRONIC_CRONTAB}" && \
    curl -fsSL -o /usr/bin/yq "${YQ_URL}" && \
        chmod 755 /usr/bin/yq && \
    apt-get -q -y --purge remove patch git && \
      apt-get -q -y --purge autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    groupadd --gid ${DEFAULT_GID} ${PUSER} && \
      useradd -m --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} && \
      usermod -a -G tty ${PUSER} && \
    mkdir -p /opt/unit "${NETBOX_DEVICETYPE_LIBRARY_PATH}" && \
    chown -R $PUSER:root /etc/netbox /opt/unit "${NETBOX_PATH}" && \
    cd "$(dirname "${NETBOX_DEVICETYPE_LIBRARY_PATH}")" && \
        curl -sSL "${NETBOX_DEVICETYPE_LIBRARY_URL}" | tar xzf - -C ./"$(basename "${NETBOX_DEVICETYPE_LIBRARY_PATH}")" --strip-components 1 && \
    mkdir -p "${NETBOX_PATH}/netbox/${BASE_PATH}" && \
      mv "${NETBOX_PATH}/netbox/static" "${NETBOX_PATH}/netbox/${BASE_PATH}/static" && \
      jq '. += { "settings": { "http": { "discard_unsafe_fields": false } } }' /etc/unit/nginx-unit.json | jq 'del(.listeners."[::]:8080")' | jq 'del(.listeners."[::]:8081")' | jq ".routes.main[0].match.uri = \"/${BASE_PATH}/static/*\"" > /etc/unit/nginx-unit-new.json && \
      mv /etc/unit/nginx-unit-new.json /etc/unit/nginx-unit.json && \
      chmod 644 /etc/unit/nginx-unit.json && \
    tr -cd '\11\12\15\40-\176' < "${NETBOX_PATH}/netbox/${BASE_PATH}/configuration.py" > "${NETBOX_PATH}/netbox/${BASE_PATH}/configuration_ascii.py" && \
      mv "${NETBOX_PATH}/netbox/${BASE_PATH}/configuration_ascii.py" "${NETBOX_PATH}/netbox/${BASE_PATH}/configuration.py" && \
    sed -i "s/\('CENSUS_REPORTING_ENABLED',[[:space:]]*\)True/\1False/" "${NETBOX_PATH}/netbox/${BASE_PATH}/settings.py" && \
    sed -i -E 's@^([[:space:]]*\-\-(state|tmp))([[:space:]])@\1dir\3@g' "${NETBOX_PATH}/launch-netbox.sh"

COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
COPY --chmod=755 netbox/scripts/* /usr/local/bin/
COPY --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
COPY --chmod=644 netbox/supervisord.conf /etc/supervisord.conf
COPY --chmod=644 netbox/preload/*.yml $NETBOX_PRELOAD_PATH/

EXPOSE 9001

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "netbox"]

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
