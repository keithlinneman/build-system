FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    git \
    curl \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Add your scripts
COPY . /build-system/
RUN chmod +x /build-system/build.sh /build-system/steps/*.sh

WORKDIR /build-system