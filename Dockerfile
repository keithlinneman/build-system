# pull in aws cli v2 pinned version
FROM amazon/aws-cli:2.33.8 AS awscli
# pull in golang pinned version
FROM golang:1.25.6-bookworm AS golang
# Using minimal debian for now, pulling latest for build env
FROM debian:bookworm-slim

COPY --from=awscli /usr/local/aws-cli /usr/local/aws-cli
RUN ln -s /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws

COPY --from=golang /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"

# Install necessary packages
RUN apt-get update && apt-get install -y \
    git \
    curl \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy build system files
COPY . /build-system/

# Make build scripts executable
RUN chmod +x /build-system/build.sh /build-system/steps/*.sh

# Set working directory to the build-system root
WORKDIR /build-system