# build ####################################################################
FROM amazonlinux:2 AS build

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

# set up build environment for dashboard plugins built from source

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "dashboarder"
ENV PGROUP "dashboarder"

ENV TERM xterm

ARG OPENSEARCH_VERSION="1.2.4"
ENV OPENSEARCH_VERSION $OPENSEARCH_VERSION

ARG OPENSEARCH_DASHBOARDS_VERSION="1.2.0"
ENV OPENSEARCH_DASHBOARDS_VERSION $OPENSEARCH_DASHBOARDS_VERSION

# base system dependencies for checking out and building plugins

USER root

RUN amazon-linux-extras install -y epel && \
    yum install -y curl patch procps psmisc tar zip unzip gcc-c++ make moreutils jq git && \
    groupadd -g ${DEFAULT_GID} ${PGROUP} && \
    adduser -u ${DEFAULT_UID} -d /home/${PUSER} -s /bin/bash -G ${PGROUP} -g ${PUSER} ${PUSER} && \
    mkdir -p /usr/share && \
    git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch --branch "${OPENSEARCH_VERSION}" https://github.com/opensearch-project/OpenSearch /usr/share/opensearch && \
    git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch --branch "${OPENSEARCH_DASHBOARDS_VERSION}" https://github.com/opensearch-project/OpenSearch-Dashboards /usr/share/opensearch-dashboards && \
    chown -R ${DEFAULT_UID}:${DEFAULT_GID} /usr/share/opensearch-dashboards /usr/share/opensearch

# build plugins as non-root

USER ${PUSER}

# use nodenv (https://github.com/nodenv/nodenv) to manage nodejs/yarn

ENV PATH "/home/${PUSER}/.nodenv/bin:${PATH}"

RUN git clone --single-branch --depth=1 --recurse-submodules --shallow-submodules https://github.com/nodenv/nodenv.git /home/${PUSER}/.nodenv && \
    cd /home/${PUSER}/.nodenv && \
    ./src/configure && \
    make -C src && \
    cd /tmp && \
    eval "$(nodenv init -)" && \
    mkdir -p "$(nodenv root)"/plugins && \
    git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch https://github.com/nodenv/node-build.git "$(nodenv root)"/plugins/node-build && \
    git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch https://github.com/nodenv/nodenv-update.git "$(nodenv root)"/plugins/nodenv-update && \
    git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch https://github.com/pine/nodenv-yarn-install.git "$(nodenv root)"/plugins/nodenv-yarn-install && \
    nodenv install "$(cat /usr/share/opensearch-dashboards/.node-version)" && \
    nodenv global "$(cat /usr/share/opensearch-dashboards/.node-version)"

# check out and build plugins

RUN eval "$(nodenv init -)" && \
    mkdir -p /usr/share/opensearch-dashboards/plugins && \
    git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch --branch opensearch-dashboards-compatibility https://github.com/mmguero-dev/kbn_sankey_vis.git /usr/share/opensearch-dashboards/plugins/sankey_vis && \
    cd /usr/share/opensearch-dashboards/plugins/sankey_vis && \
    yarn osd bootstrap && \
    yarn install && \
    yarn build --opensearch-dashboards-version "${OPENSEARCH_DASHBOARDS_VERSION}" && \
    mv ./build/kbnSankeyVis-"${OPENSEARCH_DASHBOARDS_VERSION}".zip ./build/kbnSankeyVis.zip

# runtime ##################################################################

FROM opensearchproject/opensearch-dashboards:1.2.0

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/opensearch-dashboards'
LABEL org.opencontainers.image.description='Malcolm container providing OpenSearch Dashboards'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "opensearch-dashboards"
ENV PGROUP "opensearch-dashboards"
ENV PUSER_PRIV_DROP true

ENV TERM xterm

ARG OPENSEARCH_URL="http://opensearch:9200"
ARG CREATE_OS_ARKIME_SESSION_INDEX="true"
ARG ARKIME_INDEX_PATTERN="arkime_sessions3-*"
ARG ARKIME_INDEX_PATTERN_ID="arkime_sessions3-*"
ARG ARKIME_INDEX_TIME_FIELD="firstPacket"
ARG NODE_OPTIONS="--max_old_space_size=4096"


ENV CREATE_OS_ARKIME_SESSION_INDEX $CREATE_OS_ARKIME_SESSION_INDEX
ENV ARKIME_INDEX_PATTERN $ARKIME_INDEX_PATTERN
ENV ARKIME_INDEX_PATTERN_ID $ARKIME_INDEX_PATTERN_ID
ENV ARKIME_INDEX_TIME_FIELD $ARKIME_INDEX_TIME_FIELD
ENV OPENSEARCH_DEFAULT_DASHBOARD $OPENSEARCH_DEFAULT_DASHBOARD
ENV PATH="/data:${PATH}"
ENV OPENSEARCH_URL $OPENSEARCH_URL
ENV NODE_OPTIONS $NODE_OPTIONS

USER root

COPY --from=build /usr/share/opensearch-dashboards/plugins/sankey_vis/build/kbnSankeyVis.zip /tmp/kbnSankeyVis.zip

RUN yum install -y curl psmisc util-linux zip unzip && \
    usermod -a -G tty ${PUSER} && \
    # Malcolm manages authentication and encryption via NGINX reverse proxy
    /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin remove securityDashboards --allow-root && \
    cd /usr/share/opensearch-dashboards/plugins && \
    /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install file:///tmp/kbnSankeyVis.zip --allow-root && \
    yum clean all && \
    rm -rf /var/cache/yum

ADD dashboards/opensearch_dashboards.yml /usr/share/opensearch-dashboards/config/opensearch_dashboards.yml
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/share/opensearch-dashboards/opensearch-dashboards-docker-entrypoint.sh"]

EXPOSE 5601

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
