FROM netboxcommunity/netbox:v4.4.8

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
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
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "ubuntu"
ENV PGROUP "ubuntu"
ENV PUSER_PRIV_DROP true
USER root

ENV NETBOX_INITIALIZERS_VERSION "v4.4.0"
ENV NETBOX_TOPOLOGY_VERSION "4.4.0"
ENV NETBOX_HEALTHCHECK_VERSION "0.2.0"

ENV YQ_VERSION "4.49.2"
ENV YQ_URL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_"

ENV NETBOX_DEVICETYPE_LIBRARY_IMPORT_URL "https://codeload.github.com/mmguero-dev/Device-Type-Library-Import/tar.gz/develop"
ENV NETBOX_DEVICETYPE_LIBRARY_URL "https://codeload.github.com/netbox-community/devicetype-library/tar.gz/master"

ARG NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH="/opt/netbox-devicetype-library-import"

ARG NETBOX_DEFAULT_SITE=Malcolm
ARG NETBOX_PRELOAD_PATH="/opt/netbox-preload"
ARG NETBOX_CUSTOM_PLUGINS_PATH="/opt/netbox-custom-plugins"
ARG NETBOX_CONFIG_PATH="/etc/netbox/config"

ENV NETBOX_PATH /opt/netbox
ENV NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH $NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH
ENV NETBOX_DEFAULT_SITE $NETBOX_DEFAULT_SITE
ENV NETBOX_PRELOAD_PATH $NETBOX_PRELOAD_PATH
ENV NETBOX_CUSTOM_PLUGINS_PATH $NETBOX_CUSTOM_PLUGINS_PATH
ENV NETBOX_CONFIG_PATH $NETBOX_CONFIG_PATH

ADD --chmod=644 netbox/patch/* /tmp/netbox-patches/
ADD --chmod=644 netbox/requirements.txt /usr/local/src/
ADD --chmod=644 netbox/config/* /tmp/netbox-config/

RUN export BINARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    mv /etc/apt/sources.list.d/unit.list /tmp/ && \
      apt-get -q update && \
      apt-get install -q -y --no-install-recommends gpg && \
      curl -s https://nginx.org/keys/nginx_signing.key | gpg --dearmor > /usr/share/keyrings/nginx-keyring.gpg && \
      mv /tmp/unit.list /etc/apt/sources.list.d/unit.list && \
    apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
      gcc \
      file \
      git \
      gpg \
      jq \
      libmagic-dev \
      libmagic1 \
      libpq-dev \
      libpq5 \
      patch \
      postgresql-client \
      procps \
      psmisc \
      python3-dev \
      python3-pip \
      python3-setuptools \
      python3-wheel \
      ripgrep \
      rsync \
      tini && \
    curl -fsSL -o /tmp/get-pip.py "https://bootstrap.pypa.io/get-pip.py" && \
      "${NETBOX_PATH}/venv/bin/python" /tmp/get-pip.py && \
    "${NETBOX_PATH}/venv/bin/python" -m pip install --break-system-packages --no-compile --no-cache-dir -r /usr/local/src/requirements.txt && \
    cd "${NETBOX_PATH}" && \
      bash -c 'for i in /tmp/netbox-patches/*; do patch -p 1 -r - --no-backup-if-mismatch < $i || true; done' && \
    curl -fsSL -o /usr/bin/yq "${YQ_URL}${BINARCH}" && \
        chmod 755 /usr/bin/yq && \
    usermod -a -G tty ${PUSER} && \
    mkdir -p /opt/unit "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH}" "${NETBOX_PRELOAD_PATH}" && \
    cp /tmp/netbox-config/* "${NETBOX_CONFIG_PATH}" && \
    chown -R $PUSER:root /etc/netbox /opt/unit "${NETBOX_PATH}" && \
    cd "$(dirname "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH}")" && \
        curl -sSL "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_URL}" | tar xzf - -C ./"$(basename "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH}")" --strip-components 1 && \
    cd "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH}" && \
      "${NETBOX_PATH}/venv/bin/python" -m pip install --break-system-packages --no-compile --no-cache-dir -r ./requirements.txt && \
      sed -i "s/self.pull_repo()/pass/g" ./repo.py && \
      mkdir -p ./repo && \
      curl -sSL "${NETBOX_DEVICETYPE_LIBRARY_URL}" | tar xzf - -C ./repo --strip-components 1 && \
      rm -rf ./repo/device-types/WatchGuard && \
    mkdir -p "${NETBOX_PATH}/netbox/netbox" "${NETBOX_CUSTOM_PLUGINS_PATH}/requirements" && \
      jq '. += { "settings": { "http": { "discard_unsafe_fields": false } } }' /etc/unit/nginx-unit.json | jq 'del(.listeners."[::]:8080")' | jq 'del(.listeners."[::]:8081")' | jq '.routes.main[0].action.share = "`/opt/netbox/netbox${uri.substring(7)}`"' | jq '.routes.main[0].match.uri = "/netbox/static/*"' | jq '.routes.status[0].match.uri = "/netbox/status/*"' > /etc/unit/nginx-unit-new.json && \
      mv /etc/unit/nginx-unit-new.json /etc/unit/nginx-unit.json && \
      chmod 644 /etc/unit/nginx-unit.json && \
    tr -cd '\11\12\15\40-\176' < "${NETBOX_PATH}/netbox/netbox/configuration.py" > "${NETBOX_PATH}/netbox/netbox/configuration_ascii.py" && \
      mv "${NETBOX_PATH}/netbox/netbox/configuration_ascii.py" "${NETBOX_PATH}/netbox/netbox/configuration.py" && \
    sed -i "s/\('CENSUS_REPORTING_ENABLED',[[:space:]]*\)True/\1False/" "${NETBOX_PATH}/netbox/netbox/settings.py" && \
    sed -i -E 's@^([[:space:]]*\-\-(state|tmp))([[:space:]])@\1dir\3@g' "${NETBOX_PATH}/launch-netbox.sh" && \
    sed -i '/\/opt\/netbox\/venv\/bin\/activate/a \\n# Install custom plugins \npython3 /usr/local/bin/netbox_install_plugins.py' /opt/netbox/docker-entrypoint.sh && \
    apt-get -q -y --purge remove patch gcc libpq-dev python3-dev gpg && \
      apt-get -q -y --purge autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/netbox.sh /usr/local/bin/container_health.sh
ADD --chmod=755 netbox/scripts/* /usr/local/bin/
ADD --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_constants.py /usr/local/bin/
ADD --chmod=644 netbox/supervisord.conf /etc/supervisord.conf
ADD --chmod=644 netbox/preload/*.yml $NETBOX_PRELOAD_PATH/

EXPOSE 9001

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "netbox"]

CMD ["/opt/netbox/docker-entrypoint.sh", "supervisord", "-c", "/etc/supervisord.conf", "-n"]

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
