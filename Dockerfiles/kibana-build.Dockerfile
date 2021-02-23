FROM centos:7 AS build

ARG ELASTIC_VERSION="7.10.2"
ENV ELASTIC_VERSION $ELASTIC_VERSION

USER root

RUN yum install -y epel-release && \
    yum update -y && \
    yum install -y curl git patch psmisc zip unzip gcc-c++ make && \
    yum clean all

ENV PATH "/root/.nodenv/bin:${PATH}"

RUN git clone --single-branch --depth=1 --recurse-submodules https://github.com/nodenv/nodenv.git /root/.nodenv && \
    cd /root/.nodenv && \
    ./src/configure && \
    make -C src && \
    cd /tmp && \
    eval "$(nodenv init -)" && \
    mkdir -p "$(nodenv root)"/plugins && \
    git clone --depth 1 --recurse-submodules --single-branch https://github.com/nodenv/node-build.git "$(nodenv root)"/plugins/node-build && \
    git clone --depth 1 --recurse-submodules --single-branch https://github.com/nodenv/nodenv-update.git "$(nodenv root)"/plugins/nodenv-update && \
    git clone --depth 1 --recurse-submodules --single-branch https://github.com/pine/nodenv-yarn-install.git "$(nodenv root)"/plugins/nodenv-yarn-install

RUN eval "$(nodenv init -)" && \
    mkdir -p /usr/share && \
    git clone --depth 1 --recurse-submodules --single-branch --branch "v${ELASTIC_VERSION}" https://github.com/elastic/elasticsearch /usr/share/elastic && \
    git clone --depth 1 --recurse-submodules --single-branch --branch "v${ELASTIC_VERSION}" https://github.com/elastic/kibana /usr/share/kibana && \
    nodenv install "$(cat /usr/share/kibana/.node-version)" && \
    nodenv global "$(cat /usr/share/kibana/.node-version)"

RUN eval "$(nodenv init -)" && \
    mkdir -p /usr/share/kibana/plugins && \
    git clone --depth 1 --recurse-submodules --single-branch --branch feature/update_7.10.1 https://github.com/mmguero-dev/kbn_sankey_vis.git /usr/share/kibana/plugins/sankey_vis && \
    cd /usr/share/kibana/plugins/sankey_vis && \
    yarn install && \
    yarn build --kibana-version "${ELASTIC_VERSION}"
