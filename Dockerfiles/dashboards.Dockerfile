# FROM amazonlinux:2 AS build
#
# # Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.
#
# # set up build environment for dashboard plugins built from source
#
# ARG DEFAULT_UID=1000
# ARG DEFAULT_GID=1000
# ENV DEFAULT_UID $DEFAULT_UID
# ENV DEFAULT_GID $DEFAULT_GID
# ENV PUSER "opensearch-dashboards"
# ENV PGROUP "opensearch-dashboards"
#
# ENV TERM xterm
#
# ARG OPENSEARCH_VERSION="1.0.0"
# ENV OPENSEARCH_VERSION $OPENSEARCH_VERSION
#
# ARG OPENSEARCH_DASHBOARDS_VERSION="1.0.0"
# ENV OPENSEARCH_DASHBOARDS_VERSION $OPENSEARCH_DASHBOARDS_VERSION
#
# # base system dependencies for checking out and building plugins
#
# USER root
#
# RUN amazon-linux-extras install -y epel && \
#     yum install -y curl patch procps psmisc tar zip unzip gcc-c++ make moreutils jq git && \
#     groupadd -g ${DEFAULT_GID} ${PGROUP} && \
#     adduser -u ${DEFAULT_UID} -d /home/opensearch-dashboards -s /bin/bash -G ${PGROUP} -g ${PUSER} ${PUSER} && \
#     mkdir -p /usr/share && \
#     git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch --branch "${OPENSEARCH_VERSION}" https://github.com/opensearch-project/OpenSearch /usr/share/opensearch && \
#     git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch --branch "${OPENSEARCH_DASHBOARDS_VERSION}" https://github.com/opensearch-project/OpenSearch-Dashboards /usr/share/opensearch-dashboards && \
#     chown -R ${DEFAULT_UID}:${DEFAULT_GID} /usr/share/opensearch-dashboards /usr/share/opensearch
#
# # build plugins as non-root
#
# USER ${PUSER}
#
# # use nodenv (https://github.com/nodenv/nodenv) to manage nodejs/yarn
#
# ENV PATH "/home/opensearch-dashboards/.nodenv/bin:${PATH}"
#
# RUN git clone --single-branch --depth=1 --recurse-submodules --shallow-submodules https://github.com/nodenv/nodenv.git /home/opensearch-dashboards/.nodenv && \
#     cd /home/opensearch-dashboards/.nodenv && \
#     ./src/configure && \
#     make -C src && \
#     cd /tmp && \
#     eval "$(nodenv init -)" && \
#     mkdir -p "$(nodenv root)"/plugins && \
#     git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch https://github.com/nodenv/node-build.git "$(nodenv root)"/plugins/node-build && \
#     git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch https://github.com/nodenv/nodenv-update.git "$(nodenv root)"/plugins/nodenv-update && \
#     git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch https://github.com/pine/nodenv-yarn-install.git "$(nodenv root)"/plugins/nodenv-yarn-install && \
#     nodenv install "$(cat /usr/share/opensearch-dashboards/.node-version)" && \
#     nodenv global "$(cat /usr/share/opensearch-dashboards/.node-version)"
#
# # check out and build plugins
#
# RUN eval "$(nodenv init -)" && \
#     mkdir -p /usr/share/opensearch-dashboards/plugins && \
#     git clone --depth 1 --recurse-submodules --shallow-submodules --single-branch --branch master https://github.com/mmguero-dev/kbn_sankey_vis.git /usr/share/opensearch-dashboards/plugins/sankey_vis && \
#     cd /usr/share/opensearch-dashboards/plugins/sankey_vis && \
#     yarn kbn bootstrap && \
#     yarn install && \
#     yarn build --kibana-version "${ELASTIC_VERSION}" && \
#     mv ./build/kbnSankeyVis-7.10.2.zip ./build/kbnSankeyVis.zip

FROM opensearchproject/opensearch-dashboards:1.0.1

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
ARG ARKIME_INDEX_PATTERN="sessions2-*"
ARG ARKIME_INDEX_PATTERN_ID="sessions2-*"
ARG ARKIME_INDEX_TIME_FIELD="firstPacket"
ARG OPENSEARCH_DEFAULT_DASHBOARD="0ad3d7c2-3441-485e-9dfe-dbb22e84e576"
ARG NODE_OPTIONS="--max_old_space_size=4096"

ENV CREATE_OS_ARKIME_SESSION_INDEX $CREATE_OS_ARKIME_SESSION_INDEX
ENV ARKIME_INDEX_PATTERN $ARKIME_INDEX_PATTERN
ENV ARKIME_INDEX_PATTERN_ID $ARKIME_INDEX_PATTERN_ID
ENV ARKIME_INDEX_TIME_FIELD $ARKIME_INDEX_TIME_FIELD
ENV OPENSEARCH_DEFAULT_DASHBOARD $OPENSEARCH_DEFAULT_DASHBOARD
ENV OFFLINE_REGION_MAPS $OFFLINE_REGION_MAPS
ENV OFFLINE_REGION_MAPS_PORT $OFFLINE_REGION_MAPS_PORT
ENV PATH="/data:${PATH}"
ENV OPENSEARCH_URL $OPENSEARCH_URL
ENV OPENSEARCH_DEFAULT_DASHBOARD $OPENSEARCH_DEFAULT_DASHBOARD
ENV NODE_OPTIONS $NODE_OPTIONS

USER root

# curl -sSL -o /tmp/kibana-drilldown.zip "https://codeload.github.com/mmguero-dev/kibana-plugin-drilldownmenu/zip/master" && \
# cd /tmp && \
#   echo "Installing Drilldown menu plugin..." && \
#   unzip /tmp/kibana-drilldown.zip && \
#   mkdir ./kibana &&\
#   mv ./kibana-plugin-drilldownmenu-* ./kibana/kibana-plugin-drilldownmenu && \
#   cd ./kibana/kibana-plugin-drilldownmenu && \
#   sed -i "s/7\.6\.2/7\.10\.0/g" ./package.json && \
#   npm install && \bin/opensearch-dashboards-plugin
#   cd /tmp && \
#   zip -r drilldown.zip kibana --exclude ./kibana/kibana-plugin-drilldownmenu/.git\* && \
#   cd /usr/share/opensearch-dashboards/plugins && \
#   /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install file:///tmp/drilldown.zip --allow-root && \
#   rm -rf /tmp/kibana /tmp/*drilldown* && \
# cd /tmp && \
#     rm -rf /tmp/npm-*

# COPY --from=build /usr/share/opensearch-dashboards/plugins/sankey_vis/build/kbnSankeyVis.zip /tmp/kbnSankeyVis.zip
# ADD "https://github.com/dlumbrer/kbn_network/releases/download/7.10.0-1/kbn_network-7.10.0.zip" /tmp/kibana-network.zip

RUN yum install -y curl psmisc zip unzip && \
    usermod -a -G tty ${PUSER} && \
    # Malcolm manages authentication and encryption via NGINX reverse proxy
    /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin remove securityDashboards --allow-root && \
    yum clean all && \
    rm -rf /var/cache/yum

# && \
# cd /usr/share/opensearch-dashboards/plugins && \
#   /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install file:///tmp/kbnSankeyVis.zip --allow-root && \
# cd /tmp && \
#   unzip kibana-network.zip kibana/kbn_network/kibana.json kibana/kbn_network/package.json && \
#   sed -i "s/7\.10\.0/7\.10\.2/g" kibana/kbn_network/kibana.json && \
#   sed -i "s/7\.10\.0/7\.10\.2/g" kibana/kbn_network/package.json && \
#   zip kibana-network.zip kibana/kbn_network/kibana.json kibana/kbn_network/package.json && \
#   cd /usr/share/opensearch-dashboards/plugins && \
#   /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install file:///tmp/kibana-network.zip --allow-root && \
#   rm -rf /tmp/kibana-comments.zip /tmp/kibana

ADD dashboards/opensearch_dashboards.yml /usr/share/opensearch-dashboards/config/opensearch_dashboards.yml
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/local/bin/kibana-docker"]

EXPOSE 5601

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
