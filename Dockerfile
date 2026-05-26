# pull in aws cli v2 pinned version
FROM amazon/aws-cli:2.34.53 AS awscli
# pull in golang pinned version
FROM golang:1.25.10-bookworm AS golang
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
RUN curl -sSL https://github.com/oras-project/oras/releases/download/v1.3.2/oras_1.3.2_linux_amd64.tar.gz -o /tmp/oras.tar.gz \
    && echo "9229ccc6d17bb282039ad4a69abb16dcb887a5bce567c075d731d9b3c7ad8eaf  /tmp/oras.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/oras.tar.gz -C /usr/local/bin oras \
    && chmod +x /usr/local/bin/oras

# Install cosign pinned version
RUN curl -sSL https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64 -o /usr/local/bin/cosign \
    && echo "c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74  /usr/local/bin/cosign" | sha256sum -c - \
    && chmod +x /usr/local/bin/cosign

# Install syft pinned version
RUN curl -sSL https://github.com/anchore/syft/releases/download/v1.44.0/syft_1.44.0_linux_amd64.tar.gz -o /tmp/syft.tar.gz \
    && echo "0e91737aee2b5baf1d255b959630194a302335d848ff97bb07921eb6205b5f5a  /tmp/syft.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/syft.tar.gz -C /usr/local/bin syft \
    && chmod +x /usr/local/bin/syft

# Install trivy pinned version
RUN curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz -o /tmp/trivy.tar.gz \
    && echo "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy

# Install grype pinned version
RUN curl -sSL https://github.com/anchore/grype/releases/download/v0.112.0/grype_0.112.0_linux_amd64.tar.gz -o /tmp/grype.tar.gz \
    && echo "acb14a030010fe9bdb9594b4ae108d9d14ef2f926d936aa0916dc62c89c058ea  /tmp/grype.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/grype.tar.gz -C /usr/local/bin grype \
    && chmod +x /usr/local/bin/grype

# Install cyclonedx-gomod pinned version
RUN curl -sSL https://github.com/CycloneDX/cyclonedx-gomod/releases/download/v1.10.0/cyclonedx-gomod_1.10.0_linux_amd64.tar.gz -o /tmp/cyclonedx-gomod.tar.gz \
    && echo "5cce8ae99a5181be6a610ea5ed9ca9d596937cc04dc1a8f6f6b5e462d8c9900e  /tmp/cyclonedx-gomod.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/cyclonedx-gomod.tar.gz -C /usr/local/bin cyclonedx-gomod \
    && chmod +x /usr/local/bin/cyclonedx-gomod

# Install golintci-lint pinned version
RUN curl -sSL https://github.com/golangci/golangci-lint/releases/download/v2.12.2/golangci-lint-2.12.2-linux-amd64.tar.gz -o /tmp/golangci-lint.tar.gz \
    && echo "8df580d2670fed8fa984aac0507099af8df275e665215f5c7a2ae3943893a553  /tmp/golangci-lint.tar.gz" | sha256sum -c - \
    && tar -xzvf /tmp/golangci-lint.tar.gz -C /usr/local/bin --strip-components=1 golangci-lint-2.12.2-linux-amd64/golangci-lint \
    && chmod +x /usr/local/bin/golangci-lint

# Install govulncheck pinned version
RUN go install golang.org/x/vuln/cmd/govulncheck@v1.1.4

# Copy build system files
COPY . /build-system/

# Make build scripts executable
RUN chmod +x /build-system/build.sh /build-system/steps/*.sh

# Set working directory to the build-system root
WORKDIR /build-system