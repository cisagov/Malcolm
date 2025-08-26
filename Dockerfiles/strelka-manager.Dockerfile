# Strelka Manager
# Manages portions of Strelka's Redis database.
# For more information, please see: https://target.github.io/strelka/#/?id=strelka-manager
FROM golang:1.21.5 AS build
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# Copy source files and set the working directory
COPY ./strelka/src/go/ /go/src/github.com/target/strelka/src/go/
WORKDIR /go/src/github.com/target/strelka/src/go/
COPY ./strelka/go.* /go/src/github.com/target/strelka/

# Statically compile and output to /tmp
RUN go mod download && \
    CGO_ENABLED=0 go build -o /tmp/strelka-manager cmd/strelka-manager/main.go

# Initialize runtime container with non-root user
FROM alpine
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static /tini
RUN chmod a+rx /tini

USER 1001

# Copy binary to /usr/local/bin
COPY --from=build /tmp/strelka-manager /usr/local/bin/strelka-manager

ENTRYPOINT ["/tini", "--"]
CMD ["strelka-manager"]

