FROM opensearchproject/logstash-oss-with-opensearch-output-plugin:7.16.2

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/logstash-oss'
LABEL org.opencontainers.image.description='Malcolm container providing Logstash (the Apache-licensed variant)'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "logstash"
ENV PGROUP "logstash"
ENV PUSER_PRIV_DROP true

ENV TERM xterm

ARG LOGSTASH_ENRICHMENT_PIPELINE=enrichment
ARG LOGSTASH_PARSE_PIPELINE_ADDRESSES=zeek-parse
ARG LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL=internal-os
ARG LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL=external-os
ARG LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES=internal-os,external-os

ENV LOGSTASH_ENRICHMENT_PIPELINE $LOGSTASH_ENRICHMENT_PIPELINE
ENV LOGSTASH_PARSE_PIPELINE_ADDRESSES $LOGSTASH_PARSE_PIPELINE_ADDRESSES
ENV LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL $LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL
ENV LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL $LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL
ENV LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES $LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES
ENV JAVA_HOME=/usr/share/logstash/jdk

USER root

RUN yum install -y epel-release && \
    yum update -y && \
    yum install -y curl gettext python3-setuptools python3-pip python3-requests openssl && \
    yum clean all && \
    pip3 install ipaddress supervisor manuf pyyaml && \
    logstash-plugin install logstash-filter-translate logstash-filter-cidr logstash-filter-dns \
                            logstash-filter-json logstash-filter-prune logstash-filter-http \
                            logstash-filter-grok logstash-filter-geoip logstash-filter-uuid \
                            logstash-filter-kv logstash-filter-mutate logstash-filter-dissect \
                            logstash-input-beats logstash-output-elasticsearch && \
    rm -rf /root/.cache /root/.gem /root/.bundle

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/manuf-oui-parse.py /usr/local/bin/
ADD shared/bin/jdk-cacerts-auto-import.sh /usr/local/bin/
ADD logstash/maps/*.yaml /etc/
ADD logstash/config/log4j2.properties /usr/share/logstash/config/
ADD logstash/config/logstash.yml /usr/share/logstash/config/
ADD logstash/pipelines/ /usr/share/logstash/malcolm-pipelines/
ADD logstash/ruby/ /usr/share/logstash/malcolm-ruby/
ADD logstash/scripts /usr/local/bin/
ADD logstash/supervisord.conf /etc/supervisord.conf

RUN bash -c "chmod --silent 755 /usr/local/bin/*.sh /usr/local/bin/*.py || true" && \
    usermod -a -G tty ${PUSER} && \
    rm -f /usr/share/logstash/pipeline/logstash.conf && \
    rmdir /usr/share/logstash/pipeline && \
    mkdir /logstash-persistent-queue && \
    chown --silent -R ${PUSER}:root /usr/share/logstash/malcolm-pipelines /logstash-persistent-queue && \
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

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
