FROM docker.elastic.co/logstash/logstash-oss:9.2.4

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/logstash-oss'
LABEL org.opencontainers.image.description='Malcolm container providing Logstash (the Apache-licensed variant)'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID=$DEFAULT_UID
ENV DEFAULT_GID=$DEFAULT_GID
ENV PUSER="logstash"
ENV PGROUP="logstash"
ENV PUSER_PRIV_DROP=true
ENV PUSER_RLIMIT_UNLOCK=true
ENV PUSER_CHOWN="/logstash-persistent-queue"
USER root

ENV TERM=xterm
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_ROOT_USER_ACTION=ignore

ENV TINI_VERSION=v0.19.0
ENV TINI_URL=https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini

ADD --chmod=644 logstash/requirements.txt /usr/local/src/
ADD --chmod=644 logstash/config/log4j2.properties /usr/share/logstash.build/config/
ADD --chmod=644 logstash/config/logstash.yml /usr/share/logstash.build/config/logstash.orig.yml
ADD logstash/pipelines/ /usr/share/logstash.build/malcolm-pipelines/
ADD logstash/patterns/ /usr/share/logstash.build/malcolm-patterns/
ADD logstash/ruby/ /usr/share/logstash.build/malcolm-ruby/
ADD --chmod=755 logstash/scripts/*.sh /usr/local/bin/
ADD --chmod=755 logstash/scripts/*.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_constants.py /usr/local/bin/

RUN set -x && \
    microdnf -y update && \
    microdnf -y upgrade && \
    microdnf -y install \
        bash \
        ca-certificates \
        curl-minimal \
        gettext \
        git \
        jq \
        patch \
        python3-pip \
        python3-requests \
        python3-setuptools \
        rsync && \
    curl -sSLf -o /usr/bin/tini "${TINI_URL}-$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')" && \
        chmod +x /usr/bin/tini && \
    python3 -m pip install --upgrade pip setuptools wheel && \
    python3 -m pip install --no-compile --no-cache-dir -r /usr/local/src/requirements.txt && \
    export JAVA_HOME=/usr/share/logstash/jdk && \
    /usr/share/logstash/vendor/jruby/bin/jruby -S gem install bundler && \
        echo "gem 'concurrent-ruby'" >> /usr/share/logstash/Gemfile && \
        echo "gem 'deep_merge'" >> /usr/share/logstash/Gemfile && \
        echo "gem 'fuzzy-string-match'" >> /usr/share/logstash/Gemfile && \
        echo "gem 'lru_reredux', git: 'https://github.com/mmguero-dev/lru_reredux'" >> /usr/share/logstash/Gemfile && \
        echo "gem 'stringex'" >> /usr/share/logstash/Gemfile && \
        /usr/share/logstash/bin/ruby -S bundle install && \
    logstash-plugin install --preserve logstash-filter-translate logstash-filter-cidr logstash-filter-dns \
                                       logstash-filter-json logstash-filter-prune logstash-filter-http \
                                       logstash-filter-grok logstash-filter-geoip logstash-filter-uuid \
                                       logstash-filter-kv logstash-filter-mutate logstash-filter-dissect \
                                       logstash-filter-fingerprint logstash-filter-useragent \
                                       logstash-input-beats logstash-output-elasticsearch logstash-output-opensearch && \
    microdnf clean all && \
    rm -rf /tmp/* /var/tmp/* /usr/bin/jruby /root/.cache /root/.gem /root/.bundle /usr/share/logstash/pipeline && \
    rsync -a --chown=${PUSER}:${PGROUP} /usr/share/logstash.build/ /usr/share/logstash/ && \
    rm -rf /usr/share/logstash.build/ && \
    mkdir -p /logstash-persistent-queue /usr/share/logstash/config/bootstrap /usr/share/logstash/config/persist && \
    usermod -a -G tty ${PUSER} && \
    chown -R ${PUSER}:root /usr/share/logstash /logstash-persistent-queue && \
    chmod -R u+rwX,go+rX /usr/share/logstash && \
    echo "Retrieving and parsing Wireshark manufacturer database..." && \
    python3 /usr/local/bin/manuf-oui-parse.py -o /etc/vendor_macs.yaml && \
    echo "Complete."

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/logstash.sh /usr/local/bin/container_health.sh
ADD --chmod=755 shared/bin/opensearch_status.sh /usr/local/bin/
ADD --chmod=755 shared/bin/jdk-cacerts-auto-import.sh /usr/local/bin/
ADD --chmod=755 shared/bin/keystore-bootstrap.sh /usr/local/bin/
ADD --chmod=644 logstash/maps/*.yaml /etc/
ADD --chmod=644 logstash/supervisord.conf /etc/supervisord.conf

ARG LOGSTASH_ENRICHMENT_PIPELINE=enrichment
ARG LOGSTASH_PARSE_PIPELINE_ADDRESSES=zeek-parse,suricata-parse,beats-parse,filescan-parse
ARG LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL=internal-os
ARG LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL=external-os
ARG LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES=internal-os,external-os

ENV LOGSTASH_ENRICHMENT_PIPELINE=$LOGSTASH_ENRICHMENT_PIPELINE
ENV LOGSTASH_PARSE_PIPELINE_ADDRESSES=$LOGSTASH_PARSE_PIPELINE_ADDRESSES
ENV LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL=$LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL
ENV LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL=$LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL
ENV LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES=$LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES

ENV LOGSTASH_KEYSTORE_PASS="a410a267b1404c949284dee25518a917"
VOLUME ["/logstash-persistent-queue"]

EXPOSE 5044 9001 9600

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-uid-gid-setup.sh", "/usr/local/bin/service_check_passthrough.sh", "-s", "logstash"]
CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]

ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION
ENV BUILD_DATE=$BUILD_DATE
ENV MALCOLM_VERSION=$MALCOLM_VERSION
ENV VCS_REVISION=$VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
