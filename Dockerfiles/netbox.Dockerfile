FROM netboxcommunity/netbox:v4.6.10

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/netbox'
LABEL org.opencontainers.image.description='Malcolm container providing the NetBox asset management system'

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm
ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID=$DEFAULT_UID
ENV DEFAULT_GID=$DEFAULT_GID
ENV PUSER="ubuntu"
ENV PGROUP="ubuntu"
ENV PUSER_PRIV_DROP=true
USER root

ENV NETBOX_INITIALIZERS_VERSION="v4.6.2"
ENV NETBOX_TOPOLOGY_VERSION="4.5.1"
ENV NETBOX_HEALTHCHECK_VERSION="0.3.0"

ENV YQ_VERSION="4.54.1"
ENV YQ_URL="https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_"

# Keep the device type importer and library fixed and verify each archive before extracting it;
#   update each commit and SHA-256 together
ENV NETBOX_DEVICETYPE_LIBRARY_IMPORT_COMMIT="38ab87e12cc569e912a888d6c5e8b0cfd47bc915"
ENV NETBOX_DEVICETYPE_LIBRARY_IMPORT_SHA256="85d658afec394b34bb3ad1af47e1a6a556cf7d378ee2bbcf5a6cbf263336be81"
ENV NETBOX_DEVICETYPE_LIBRARY_IMPORT_URL="https://codeload.github.com/mmguero-dev/Device-Type-Library-Import/tar.gz/${NETBOX_DEVICETYPE_LIBRARY_IMPORT_COMMIT}"
ENV NETBOX_DEVICETYPE_LIBRARY_COMMIT="12b55e51aa259d75c5658b9cb7ce9a1bd1effc65"
ENV NETBOX_DEVICETYPE_LIBRARY_SHA256="78ffb15620154df8362ff70482aa9b502018584844ddf666e1cad15570e312a8"
ENV NETBOX_DEVICETYPE_LIBRARY_URL="https://codeload.github.com/netbox-community/devicetype-library/tar.gz/${NETBOX_DEVICETYPE_LIBRARY_COMMIT}"

# pip for NetBox's venv, installed from its PyPI wheel (verified against binaries.sha256)
ENV NETBOX_PIP_VERSION="25.2"
ENV NETBOX_PIP_URL="https://files.pythonhosted.org/packages/py3/p/pip/pip-${NETBOX_PIP_VERSION}-py3-none-any.whl"

ARG NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH="/opt/netbox-devicetype-library-import"

ARG NETBOX_DEFAULT_SITE=Malcolm
ARG NETBOX_PRELOAD_PATH="/opt/netbox-preload"
ARG NETBOX_CUSTOM_PLUGINS_PATH="/opt/netbox-custom-plugins"
ARG NETBOX_CUSTOM_VENV_PACKAGES_PATH="/opt/netbox-custom-python"
ARG NETBOX_CUSTOM_SCRIPTS_PATH="/opt/netbox-custom-scripts"

ENV NETBOX_PATH=/opt/netbox
ENV NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH=$NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH

ENV NETBOX_DEFAULT_SITE=$NETBOX_DEFAULT_SITE
ENV NETBOX_PRELOAD_PATH=$NETBOX_PRELOAD_PATH
ENV NETBOX_CUSTOM_PLUGINS_PATH=$NETBOX_CUSTOM_PLUGINS_PATH
ENV NETBOX_CUSTOM_VENV_PACKAGES_PATH=$NETBOX_CUSTOM_VENV_PACKAGES_PATH
ENV NETBOX_CUSTOM_SCRIPTS_PATH=$NETBOX_CUSTOM_SCRIPTS_PATH
ENV NETBOX_RUNTIME_SCRIPTS_PATH=/opt/netbox/netbox/scripts
ENV NETBOX_CONFIG_PATH=/etc/netbox/config

ARG GRANIAN_EXTRA_ARGS="--host=0.0.0.0"
ENV GRANIAN_EXTRA_ARGS=$GRANIAN_EXTRA_ARGS

ADD --chmod=644 netbox/patch/* /tmp/netbox-patches/
ADD --chmod=644 netbox/requirements.txt /usr/local/src/
ADD --chmod=644 netbox/config/* /tmp/netbox-config/

RUN --mount=type=bind,source=shared/bin/install-verified-binary.sh,target=/usr/local/share/install-verified-binary.sh,ro \
    --mount=type=bind,source=shared/checksums/binaries.sha256,target=/usr/local/share/binaries.sha256,ro \
    apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
      curl \
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
    sh /usr/local/share/install-verified-binary.sh "/tmp/pip-${NETBOX_PIP_VERSION}-py3-none-any.whl" "${NETBOX_PIP_URL}" "pip-${NETBOX_PIP_VERSION}-py3-none-any.whl" && \
      "${NETBOX_PATH}/venv/bin/python" "/tmp/pip-${NETBOX_PIP_VERSION}-py3-none-any.whl/pip" install --no-index --no-cache-dir "/tmp/pip-${NETBOX_PIP_VERSION}-py3-none-any.whl" && \
    "${NETBOX_PATH}/venv/bin/python" -m pip install --break-system-packages --no-compile --no-cache-dir -r /usr/local/src/requirements.txt && \
    cd "${NETBOX_PATH}" && \
      bash -c 'for i in /tmp/netbox-patches/*; do patch -p 1 -r - --no-backup-if-mismatch < $i || true; done' && \
    sh /usr/local/share/install-verified-binary.sh /usr/bin/yq "${YQ_URL}{arch}" "yq_${YQ_VERSION}_linux_{arch}" && \
    usermod -a -G tty ${PUSER} && \
    mkdir -p "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH}" "${NETBOX_PRELOAD_PATH}" && \
    cp /tmp/netbox-config/* "${NETBOX_CONFIG_PATH}" && \
    chown -R ${PUSER}:root /etc/netbox && \
    chown -R root:root "${NETBOX_PATH}" && \
    cd "$(dirname "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH}")" && \
        curl -fsSL -o /tmp/devicetype-library-import.tar.gz "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_URL}" && \
        echo "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_SHA256}  /tmp/devicetype-library-import.tar.gz" | sha256sum -c - && \
        tar xzf /tmp/devicetype-library-import.tar.gz -C ./"$(basename "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH}")" --strip-components 1 && \
    cd "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH}" && \
      VIRTUAL_ENV= "${NETBOX_PATH}/venv/bin/python" -m uv sync --no-dev && \
      sed -i "s/self.pull_repo()/pass/g" ./core/repo.py && \
      mkdir -p ./repo && \
      curl -fsSL -o /tmp/devicetype-library.tar.gz "${NETBOX_DEVICETYPE_LIBRARY_URL}" && \
      echo "${NETBOX_DEVICETYPE_LIBRARY_SHA256}  /tmp/devicetype-library.tar.gz" | sha256sum -c - && \
      tar xzf /tmp/devicetype-library.tar.gz -C ./repo --strip-components 1 && \
      chown -R ${PUSER}:root "${NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH}/repo" && \
    mkdir -p "${NETBOX_PATH}/netbox/netbox" "${NETBOX_CUSTOM_PLUGINS_PATH}/requirements" "${NETBOX_CUSTOM_SCRIPTS_PATH}" "${NETBOX_RUNTIME_SCRIPTS_PATH}" "${NETBOX_CUSTOM_VENV_PACKAGES_PATH}" && \
      chown --silent -R ${PUSER}:${PGROUP} "${NETBOX_CUSTOM_PLUGINS_PATH}" "${NETBOX_CUSTOM_SCRIPTS_PATH}" "${NETBOX_RUNTIME_SCRIPTS_PATH}" "${NETBOX_CUSTOM_VENV_PACKAGES_PATH}" && \
      echo "${NETBOX_CUSTOM_VENV_PACKAGES_PATH}" > "$(${NETBOX_PATH}/venv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')/netbox-extra.pth" && \
    tr -cd '\11\12\15\40-\176' < "${NETBOX_PATH}/netbox/netbox/configuration.py" > "${NETBOX_PATH}/netbox/netbox/configuration_ascii.py" && \
      mv "${NETBOX_PATH}/netbox/netbox/configuration_ascii.py" "${NETBOX_PATH}/netbox/netbox/configuration.py" && \
    sed -i "s/\('CENSUS_REPORTING_ENABLED',[[:space:]]*\)True/\1False/" "${NETBOX_PATH}/netbox/netbox/settings.py" && \
    sed -i '/\/opt\/netbox\/venv\/bin\/activate/a \\n# Install custom plugins \npython3 /usr/local/bin/netbox_install_plugins.py' /opt/netbox/docker-entrypoint.sh && \
    rm -f /opt/netbox/launch-netbox.sh /opt/netbox/super_user.py && \
      ln -s /usr/local/bin/launch-netbox.sh /opt/netbox/launch-netbox.sh && \
      ln -s /usr/local/bin/netbox_superuser_create.py /opt/netbox/super_user.py && \
    apt-get -q -y --purge remove patch gcc libpq-dev python3-dev gpg && \
      apt-get -q -y --purge autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=ghcr.io/mmguero-dev/gostatic:latest@sha256:cba944f026b430ba5db45f563b32b0ad849703ae5996d3a30ce5deffd1ef9112 --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/netbox.sh /usr/local/bin/container_health.sh
ADD --chmod=755 netbox/control-scripts/* /usr/local/bin/
# ADD --chmod=755 netbox/builtin-scripts/* $NETBOX_CUSTOM_SCRIPTS_PATH/
ADD --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_constants.py /usr/local/bin/
ADD --chmod=644 netbox/supervisord.conf /etc/supervisord.conf
ADD --chmod=644 netbox/preload/*.yml $NETBOX_PRELOAD_PATH/

EXPOSE 9001

# This is in part to handle an issue when running with rootless podman and
#   "userns_mode: keep-id". It seems that anything defined as a VOLUME
#   in the Dockerfile is getting set with an ownership of 999:999.
#   This is to override that, although I'm not yet sure if there are
#   other implications. See containers/podman#23347.
ENV PUSER_CHOWN="$NETBOX_CUSTOM_PLUGINS_PATH;$NETBOX_CUSTOM_SCRIPTS_PATH;$NETBOX_RUNTIME_SCRIPTS_PATH;$NETBOX_CUSTOM_VENV_PACKAGES_PATH"

# see PUSER_CHOWN comment above
VOLUME ["$NETBOX_CUSTOM_PLUGINS_PATH"]
VOLUME ["$NETBOX_CUSTOM_SCRIPTS_PATH"]
VOLUME ["$NETBOX_RUNTIME_SCRIPTS_PATH"]
VOLUME ["$NETBOX_CUSTOM_VENV_PACKAGES_PATH"]

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "netbox", \
            "/usr/local/bin/redis_valkey_env_map.sh"]

CMD ["/opt/netbox/docker-entrypoint.sh", "supervisord", "-c", "/etc/supervisord.conf", "-n"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION
ENV BUILD_DATE=$BUILD_DATE
ENV MALCOLM_VERSION=$MALCOLM_VERSION
ENV VCS_REVISION=$VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
