FROM registry.access.redhat.com/ubi9/ubi-minimal AS manuf-builder

COPY logstash/requirements.txt /work/
COPY scripts/malcolm_utils.py /work/
COPY scripts/malcolm_constants.py /work/
COPY logstash/scripts/manuf-oui-parse.py /work/

WORKDIR /work

RUN microdnf -y install \
        python3 \
        python3-pip \
        python3-requests \
        ca-certificates && \
    microdnf clean all && \
    python3 -m pip install --no-cache-dir -r requirements.txt && \
    python3 manuf-oui-parse.py -o vendor_macs.yaml

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
# This is to handle an issue when running with rootless podman and
#   "userns_mode: keep-id". It seems that anything defined as a VOLUME
#   in the Dockerfile is getting set with an ownership of 999:999.
#   This is to override that, although I'm not yet sure if there are
#   other implications. See containers/podman#23347.
ENV PUSER_CHOWN="/logstash-persistent-queue"
ENV PUSER_PRIV_DROP=true
ENV PUSER_RLIMIT_UNLOCK=true
USER root

ENV TERM=xterm
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_ROOT_USER_ACTION=ignore

ENV YQ_VERSION="4.50.1"
ENV YQ_URL="https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_"

ENV TINI_VERSION=v0.19.0
ENV TINI_URL=https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini

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
    export BINARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') && \
    microdnf -y install curl-minimal && \
        curl -sSL -o /tmp/epel-release.rpm https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && \
        rpm -i /tmp/epel-release.rpm && \
    microdnf -y install \
        bash \
        ca-certificates \
        gettext \
        git \
        jq \
        patch \
        supervisor \
        rsync && \
    curl -sSLf -o /usr/bin/tini "${TINI_URL}-${BINARCH}" && \
        chmod +x /usr/bin/tini && \
    curl -fsSL -o /usr/local/bin/yq "${YQ_URL}${BINARCH}" && \
        chmod 755 /usr/local/bin/yq && \
    export JAVA_HOME=/usr/share/logstash/jdk && \
    /usr/share/logstash/vendor/jruby/bin/jruby -S gem install bundler && \
        echo "gem 'concurrent-ruby'" >> /usr/share/logstash/Gemfile && \
        echo "gem 'deep_merge'" >> /usr/share/logstash/Gemfile && \
        echo "gem 'fuzzy-string-match'" >> /usr/share/logstash/Gemfile && \
        echo "gem 'lru_reredux', git: 'https://github.com/mmguero-dev/lru_reredux'" >> /usr/share/logstash/Gemfile && \
        echo "gem 'stringex'" >> /usr/share/logstash/Gemfile && \
        /usr/share/logstash/bin/ruby -S bundle install && \
    logstash-plugin install --preserve logstash-output-opensearch && \
    microdnf clean all && \
    rm -rf \
        /root/.bundle \
        /root/.cache \
        /root/.gem \
        /tmp/* \
        /usr/bin/jruby \
        /usr/share/logstash/pipeline \
        /var/lib/rpm \
        /var/lib/dnf \
        /var/tmp/* && \
    find /usr/share/logstash -name '*.jsa' -delete && \
    rsync -a --chown=${PUSER}:${PGROUP} /usr/share/logstash.build/ /usr/share/logstash/ && \
    rm -rf /usr/share/logstash.build/ && \
    mkdir -p /logstash-persistent-queue /usr/share/logstash/config/bootstrap /usr/share/logstash/config/persist && \
    usermod -a -G tty ${PUSER} && \
    chown -R ${PUSER}:root /usr/share/logstash /logstash-persistent-queue && \
    chmod -R u+rwX,go+rX /usr/share/logstash

COPY --from=manuf-builder --chmod=644 /work/vendor_macs.yaml /etc/vendor_macs.yaml
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
ARG LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL=internal-os
ARG LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL=external-os
ARG LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES=internal-os,external-os

ENV LOGSTASH_ENRICHMENT_PIPELINE=$LOGSTASH_ENRICHMENT_PIPELINE
ENV LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL=$LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL
ENV LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL=$LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL
ENV LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES=$LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES

ENV LOGSTASH_KEYSTORE_PASS="a410a267b1404c949284dee25518a917"

# see PUSER_CHOWN comment above
VOLUME ["/logstash-persistent-queue"]

EXPOSE 5044 9001 9600

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-uid-gid-setup.sh", "/usr/local/bin/service_check_passthrough.sh", "-s", "logstash"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]

ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION
ENV BUILD_DATE=$BUILD_DATE
ENV MALCOLM_VERSION=$MALCOLM_VERSION
ENV VCS_REVISION=$VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
