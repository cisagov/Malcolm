FROM centos:7 AS build

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

RUN yum install -y epel-release && \
    yum update -y && \
    yum install -y java-1.8.0-openjdk-devel curl wget tar which \
                patch libyaml-devel libffi-devel glibc-headers autoconf gcc-c++ glibc-devel \
                readline-devel zlib-devel openssl-d evel bzip2 automake libtool bison make

ENV OUIFILTER_URL "https://codeload.github.com/mmguero-dev/logstash-filter-ieee_oui/tar.gz/master"

RUN /bin/bash -lc "command curl -sSL https://rvm.io/mpapis.asc | gpg2 --import -" && \
    /bin/bash -lc "command curl -sSL https://rvm.io/pkuczynski.asc | gpg2 --import -" && \
    /bin/bash -lc "curl -L get.rvm.io | bash -s stable" && \
    /bin/bash -lc "rvm autolibs fail" && \
    /bin/bash -lc "rvm install jruby-9.2.5.0" && \
    /bin/bash -lc "rvm use jruby-9.2.5.0 --default" && \
    /bin/bash -lc "gem install bundler --no-ri --no-rdoc" && \
    cd /opt && \
      mkdir -p ./logstash-filter-ieee_oui && \
      curl -sSL "$OUIFILTER_URL" | tar xzvf - -C ./logstash-filter-ieee_oui --strip-components 1 && \
      /bin/bash -lc "cd /opt/logstash-filter-ieee_oui && bundle install && gem build logstash-filter-ieee_oui.gemspec && bundle info logstash-filter-ieee_oui"

FROM docker.elastic.co/logstash/logstash-oss:7.10.0

LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
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
ARG LOGSTASH_ELASTICSEARCH_PIPELINE_ADDRESS_INTERNAL=internal-es
ARG LOGSTASH_ELASTICSEARCH_PIPELINE_ADDRESS_EXTERNAL=external-es
ARG LOGSTASH_ELASTICSEARCH_OUTPUT_PIPELINE_ADDRESSES=internal-es,external-es

ENV LOGSTASH_ENRICHMENT_PIPELINE $LOGSTASH_ENRICHMENT_PIPELINE
ENV LOGSTASH_PARSE_PIPELINE_ADDRESSES $LOGSTASH_PARSE_PIPELINE_ADDRESSES
ENV LOGSTASH_ELASTICSEARCH_PIPELINE_ADDRESS_INTERNAL $LOGSTASH_ELASTICSEARCH_PIPELINE_ADDRESS_INTERNAL
ENV LOGSTASH_ELASTICSEARCH_PIPELINE_ADDRESS_EXTERNAL $LOGSTASH_ELASTICSEARCH_PIPELINE_ADDRESS_EXTERNAL
ENV LOGSTASH_ELASTICSEARCH_OUTPUT_PIPELINE_ADDRESSES $LOGSTASH_ELASTICSEARCH_OUTPUT_PIPELINE_ADDRESSES

USER root

COPY --from=build /opt/logstash-filter-ieee_oui /opt/logstash-filter-ieee_oui

RUN yum install -y epel-release && \
    yum update -y && \
    yum install -y curl gettext python-setuptools python-pip python-requests python-yaml && \
    yum clean all && \
    pip install py2-ipaddress supervisor && \
    logstash-plugin install logstash-filter-translate logstash-filter-cidr logstash-filter-dns \
                            logstash-filter-json logstash-filter-prune logstash-filter-http \
                            logstash-filter-grok logstash-filter-geoip logstash-filter-uuid \
                            logstash-filter-kv logstash-filter-mutate logstash-filter-dissect \
                            logstash-input-beats logstash-output-elasticsearch && \
    logstash-plugin install /opt/logstash-filter-ieee_oui/logstash-filter-ieee_oui-1.0.6.gem && \
    rm -rf /opt/logstash-filter-ieee_oui /root/.cache /root/.gem /root/.bundle

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD logstash/maps/*.yaml /etc/
ADD logstash/config/log4j2.properties /usr/share/logstash/config/
ADD logstash/config/logstash.yml /usr/share/logstash/config/
ADD logstash/pipelines/ /usr/share/logstash/malcolm-pipelines/
ADD logstash/scripts /usr/local/bin/
ADD logstash/supervisord.conf /etc/supervisord.conf

RUN bash -c "chmod --silent 755 /usr/local/bin/*.sh /usr/local/bin/*.py || true" && \
    usermod -a -G tty ${PUSER} && \
    rm -f /usr/share/logstash/pipeline/logstash.conf && \
    rmdir /usr/share/logstash/pipeline && \
    mkdir /logstash-persistent-queue && \
    chown --silent -R ${PUSER}:root /usr/share/logstash/malcolm-pipelines /logstash-persistent-queue && \
    curl -sSL -o /usr/share/logstash/config/oui.txt "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf" && \
      ( awk -F '\t' '{gsub(":", "", $1); if (length($1) == 6) {if ($3) {print $1"\t"$3} else if ($2) {print $1"\t"$2}}}' /usr/share/logstash/config/oui.txt > /usr/share/logstash/config/oui-logstash.txt) && \
      python /usr/local/bin/ja3_build_list.py -o /etc/ja3.yaml

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

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
