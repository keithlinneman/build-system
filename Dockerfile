# pull in aws cli v2 pinned version
FROM amazon/aws-cli:2.33.8 AS awscli
# pull in golang pinned version
FROM golang:1.25.7-bookworm AS golang
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
    make \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Install jq pinned version
RUN curl -sSL https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-amd64 -o /usr/local/bin/jq \
    && echo "020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d  /usr/local/bin/jq" | sha256sum -c - \
    && chmod +x /usr/local/bin/jq

# Install oras pinned version
RUN curl -sSL https://github.com/oras-project/oras/releases/download/v1.3.1/oras_1.3.1_linux_amd64.tar.gz -o /tmp/oras.tar.gz \
    && echo "d52c4af76ce6a3ceb8579e51fb751a43ac051cca67f965f973a0b0e897a2bb86  /tmp/oras.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/oras.tar.gz -C /usr/local/bin oras \
    && chmod +x /usr/local/bin/oras

# Install cosign pinned version
RUN curl -sSL https://github.com/sigstore/cosign/releases/download/v3.0.5/cosign-linux-amd64 -o /usr/local/bin/cosign \
    && echo "db15cc99e6e4837daabab023742aaddc3841ce57f193d11b7c3e06c8003642b2  /usr/local/bin/cosign" | sha256sum -c - \
    && chmod +x /usr/local/bin/cosign

# Install syft pinned version
RUN curl -sSL https://github.com/anchore/syft/releases/download/v1.42.3/syft_1.42.3_linux_amd64.tar.gz -o /tmp/syft.tar.gz \
    && echo "0d6be741479eddd2c8644a288990c04f3df0d609bbc1599a005532a9dff63509  /tmp/syft.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/syft.tar.gz -C /usr/local/bin syft \
    && chmod +x /usr/local/bin/syft

# Install trivy pinned version
RUN curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz -o /tmp/trivy.tar.gz \
    && echo "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy

# Install grype pinned version
RUN curl -sSL https://github.com/anchore/grype/releases/download/v0.110.0/grype_0.110.0_linux_amd64.tar.gz -o /tmp/grype.tar.gz \
    && echo "aaa98d27d2d7efd9317c6a1ad6d9b15f3e65bab320e7d03bde41e251387bb71c  /tmp/grype.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/grype.tar.gz -C /usr/local/bin grype \
    && chmod +x /usr/local/bin/grype

# Install cyclonedx-gomod pinned version
RUN curl -sSL https://github.com/CycloneDX/cyclonedx-gomod/releases/download/v1.10.0/cyclonedx-gomod_1.10.0_linux_amd64.tar.gz -o /tmp/cyclonedx-gomod.tar.gz \
    && echo "5cce8ae99a5181be6a610ea5ed9ca9d596937cc04dc1a8f6f6b5e462d8c9900e  /tmp/cyclonedx-gomod.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/cyclonedx-gomod.tar.gz -C /usr/local/bin cyclonedx-gomod \
    && chmod +x /usr/local/bin/cyclonedx-gomod

# Install golintci-lint pinned version
RUN curl -sSL https://github.com/golangci/golangci-lint/releases/download/v2.11.3/golangci-lint-2.11.3-linux-amd64.tar.gz -o /tmp/golangci-lint.tar.gz \
    && echo "87bb8cddbcc825d5778b64e8a91b46c0526b247f4e2f2904dea74ec7450475d1  /tmp/golangci-lint.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/golangci-lint.tar.gz -C /usr/local/bin --strip-components=1 golangci-lint-2.11.3-linux-amd64/golangci-lint \
    && chmod +x /usr/local/bin/golangci-lint

# Install govulncheck pinned version
RUN go install golang.org/x/vuln/cmd/govulncheck@v1.1.4

# Copy build system files
COPY . /build-system/

# Make build scripts executable
RUN chmod +x /build-system/build.sh /build-system/steps/*.sh

# Set working directory to the build-system root
WORKDIR /build-system