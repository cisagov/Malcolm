FROM docker.elastic.co/logstash/logstash-oss:8.10.0

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
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "logstash"
ENV PGROUP "logstash"
ENV PUSER_PRIV_DROP true
ENV PUSER_RLIMIT_UNLOCK true

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ENV TINI_VERSION v0.19.0

ARG LOGSTASH_ENRICHMENT_PIPELINE=enrichment
ARG LOGSTASH_PARSE_PIPELINE_ADDRESSES=zeek-parse,suricata-parse,beats-parse
ARG LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL=internal-os
ARG LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL=external-os
ARG LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES=internal-os,external-os
ARG LOGSTASH_NETBOX_ENRICHMENT=false
ARG LOGSTASH_NETBOX_ENRICHMENT_VERBOSE=false
ARG LOGSTASH_NETBOX_ENRICHMENT_LOOKUP_SERVICE=true
ARG LOGSTASH_NETBOX_AUTO_POPULATE=false

ENV LOGSTASH_ENRICHMENT_PIPELINE $LOGSTASH_ENRICHMENT_PIPELINE
ENV LOGSTASH_PARSE_PIPELINE_ADDRESSES $LOGSTASH_PARSE_PIPELINE_ADDRESSES
ENV LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL $LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL
ENV LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL $LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL
ENV LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES $LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES
ENV LOGSTASH_NETBOX_ENRICHMENT $LOGSTASH_NETBOX_ENRICHMENT
ENV LOGSTASH_NETBOX_ENRICHMENT_VERBOSE $LOGSTASH_NETBOX_ENRICHMENT_VERBOSE
ENV LOGSTASH_NETBOX_ENRICHMENT_LOOKUP_SERVICE $LOGSTASH_NETBOX_ENRICHMENT_LOOKUP_SERVICE
ENV LOGSTASH_NETBOX_AUTO_POPULATE $LOGSTASH_NETBOX_AUTO_POPULATE

USER root

ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /usr/bin/tini

RUN set -x && \
    apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install \
        curl \
        gettext \
        patch \
        python3-setuptools \
        python3-pip \
        python3-requests \
        rsync \
        tini && \
    chmod +x /usr/bin/tini && \
    pip3 install ipaddress supervisor manuf pyyaml && \
    export JAVA_HOME=/usr/share/logstash/jdk && \
    /usr/share/logstash/vendor/jruby/bin/jruby -S gem install bundler && \
    echo "gem 'lru_cache'" >> /usr/share/logstash/Gemfile && \
    echo "gem 'deep_merge'" >> /usr/share/logstash/Gemfile && \
    echo "gem 'fuzzy-string-match'" >> /usr/share/logstash/Gemfile && \
    echo "gem 'stringex'" >> /usr/share/logstash/Gemfile && \
    echo "gem 'psych'" >> /usr/share/logstash/Gemfile && \
    /usr/share/logstash/bin/ruby -S bundle install && \
    logstash-plugin install --preserve logstash-filter-translate logstash-filter-cidr logstash-filter-dns \
                                       logstash-filter-json logstash-filter-prune logstash-filter-http \
                                       logstash-filter-grok logstash-filter-geoip logstash-filter-uuid \
                                       logstash-filter-kv logstash-filter-mutate logstash-filter-dissect \
                                       logstash-filter-fingerprint logstash-filter-useragent \
                                       logstash-input-beats logstash-output-elasticsearch logstash-output-opensearch && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove && \
        apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/bin/jruby \
           /root/.cache /root/.gem /root/.bundle

COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
COPY --chmod=755 shared/bin/opensearch_status.sh /usr/local/bin/
COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
COPY --chmod=755 shared/bin/manuf-oui-parse.py /usr/local/bin/
COPY --chmod=755 shared/bin/jdk-cacerts-auto-import.sh /usr/local/bin/
COPY --chmod=755 shared/bin/keystore-bootstrap.sh /usr/local/bin/
ADD logstash/maps/*.yaml /etc/
ADD logstash/config/log4j2.properties /usr/share/logstash/config/
ADD logstash/config/logstash.yml /usr/share/logstash/config/logstash.orig.yml
ADD logstash/pipelines/ /usr/share/logstash/malcolm-pipelines/
ADD logstash/patterns/ /usr/share/logstash/malcolm-patterns/
ADD logstash/ruby/ /usr/share/logstash/malcolm-ruby/
ADD logstash/scripts /usr/local/bin/
ADD scripts/malcolm_utils.py /usr/local/bin/
ADD logstash/supervisord.conf /etc/supervisord.conf

RUN bash -c "chmod --silent 755 /usr/local/bin/*.sh /usr/local/bin/*.py || true" && \
    usermod -a -G tty ${PUSER} && \
    rm -f /usr/share/logstash/pipeline/logstash.conf && \
    rmdir /usr/share/logstash/pipeline && \
    mkdir -p /logstash-persistent-queue \
             /usr/share/logstash/config/bootstrap \
             /usr/share/logstash/config/persist && \
    chown --silent -R ${PUSER}:root \
        /usr/share/logstash \
        /logstash-persistent-queue && \
    echo "Retrieving and parsing Wireshark manufacturer database..." && \
    python3 /usr/local/bin/manuf-oui-parse.py -o /etc/vendor_macs.yaml && \
    echo "Retrieving JA3 fingerprint lists..." && \
    python3 /usr/local/bin/ja3_build_list.py -o /etc/ja3.yaml && \
    echo "Complete."

# As the keystore is encapsulated in logstash, this isn't really necessary. It's included
# here just to suppress the prompt when creating the keystore. If you're concerned about it
# you could change or remove this from the Dockerfile, and/or override it with your
# own envrionment variable at runtime.
ENV LOGSTASH_KEYSTORE_PASS "a410a267b1404c949284dee25518a917"

VOLUME ["/logstash-persistent-queue"]

EXPOSE 5044
EXPOSE 9001
EXPOSE 9600

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "logstash"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
