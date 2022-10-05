FROM amazonlinux:2 AS build

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

RUN amazon-linux-extras install -y epel && \
    yum install -y \
      autoconf \
      automake \
      bison \
      bzip2 \
      curl \
      gcc-c++ \
      glibc-devel \
      glibc-headers \
      java-1.8.0-openjdk \
      java-latest-openjdk-devel \
      libffi-devel \
      libtool \
      libyaml-devel \
      make \
      openssl-devel \
      patch \
      procps \
      readline-devel \
      tar \
      wget \
      which \
      zlib-devel

RUN /bin/bash -lc "command curl -sSL https://rvm.io/mpapis.asc | gpg2 --import -" && \
    /bin/bash -lc "command curl -sSL https://rvm.io/pkuczynski.asc | gpg2 --import -" && \
    /bin/bash -lc "curl -L get.rvm.io | bash -s stable" && \
    /bin/bash -lc "rvm autolibs fail" && \
    /bin/bash -lc "rvm get head" && \
    /bin/bash -lc "rvm install jruby-9.3.1.0" && \
    /bin/bash -lc "rvm use jruby-9.3.1.0 --default" && \
    /bin/bash -lc "gem install bundler --no-document"

ENV FINGERPRINT_URL "https://codeload.github.com/logstash-plugins/logstash-filter-fingerprint/tar.gz/main"

RUN cd /opt && \
    mkdir -p ./logstash-filter-fingerprint && \
    curl -sSL "$FINGERPRINT_URL" | tar xzvf - -C ./logstash-filter-fingerprint --strip-components 1 && \
    sed -i "s/\('logstash-mixin-ecs_compatibility_support'\),.*/\1/" ./logstash-filter-fingerprint/logstash-filter-fingerprint.gemspec && \
    /bin/bash -lc "export LS_JAVA_HOME=$(realpath $(dirname $(find /usr/lib/jvm -name javac -type f))/../) && cd /opt/logstash-filter-fingerprint && ( bundle install || bundle install ) && gem build logstash-filter-fingerprint.gemspec && bundle info logstash-filter-fingerprint"

FROM opensearchproject/logstash-oss-with-opensearch-output-plugin:7.16.3

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
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
ARG LOGSTASH_PARSE_PIPELINE_ADDRESSES=zeek-parse,suricata-parse,beats-parse
ARG LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL=internal-os
ARG LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL=external-os
ARG LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES=internal-os,external-os

ENV LOGSTASH_ENRICHMENT_PIPELINE $LOGSTASH_ENRICHMENT_PIPELINE
ENV LOGSTASH_PARSE_PIPELINE_ADDRESSES $LOGSTASH_PARSE_PIPELINE_ADDRESSES
ENV LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL $LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL
ENV LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL $LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL
ENV LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES $LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES
ENV LS_JAVA_HOME=/usr/share/logstash/jdk

USER root

COPY --from=build /opt/logstash-filter-fingerprint /opt/logstash-filter-fingerprint

RUN yum install -y epel-release && \
    yum upgrade -y && \
    yum install -y curl gettext patch python3-setuptools python3-pip python3-requests openssl && \
    yum clean all && \
    pip3 install ipaddress supervisor manuf pyyaml && \
    logstash-plugin install --preserve logstash-filter-translate logstash-filter-cidr logstash-filter-dns \
                                       logstash-filter-json logstash-filter-prune logstash-filter-http \
                                       logstash-filter-grok logstash-filter-geoip logstash-filter-uuid \
                                       logstash-filter-kv logstash-filter-mutate logstash-filter-dissect \
                                       logstash-filter-useragent \
                                       logstash-input-beats logstash-output-elasticsearch && \
    logstash-plugin install /opt/logstash-filter-fingerprint/logstash-filter-fingerprint-*.gem && \
    rm -rf /opt/logstash-filter-fingerprint /root/.cache /root/.gem /root/.bundle

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/manuf-oui-parse.py /usr/local/bin/
ADD shared/bin/jdk-cacerts-auto-import.sh /usr/local/bin/
ADD logstash/maps/*.yaml /etc/
ADD logstash/config/log4j2.properties /usr/share/logstash/config/
ADD logstash/config/logstash.yml /usr/share/logstash/config/logstash.orig.yml
ADD logstash/pipelines/ /usr/share/logstash/malcolm-pipelines/
ADD logstash/patterns/ /usr/share/logstash/malcolm-patterns/
ADD logstash/ruby/ /usr/share/logstash/malcolm-ruby/
ADD logstash/scripts /usr/local/bin/
ADD scripts/malcolm_common.py /usr/local/bin/
ADD logstash/supervisord.conf /etc/supervisord.conf

RUN bash -c "chmod --silent 755 /usr/local/bin/*.sh /usr/local/bin/*.py || true" && \
    usermod -a -G tty ${PUSER} && \
    rm -f /usr/share/logstash/pipeline/logstash.conf && \
    rmdir /usr/share/logstash/pipeline && \
    mkdir /logstash-persistent-queue && \
    chown --silent -R ${PUSER}:root \
        /usr/share/logstash/config/logstash*.yml \
        /usr/share/logstash/malcolm-pipelines \
        /usr/share/logstash/malcolm-patterns \
        /usr/share/logstash/malcolm-ruby \
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

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
