# SPDX-License-Identifier: Apache-2.0
#!BuildTag: suse/agentic/mcp/multi-linux-manager:latest suse/agentic/mcp/multi-linux-manager:%PKG_VERSION% suse/agentic/mcp/multi-linux-manager:%PKG_VERSION_MINOR% suse/agentic/mcp/multi-linux-manager:%PKG_VERSION%.%RELEASE%
FROM bci/python:3.13

# Define labels according to https://en.opensuse.org/Building_derived_containers
# labelprefix=org.opensuse.uyuni-ai.mcp-server-uyuni
LABEL org.opencontainers.image.title="MCP Server MLM container"
LABEL org.opencontainers.image.description="This contains mcp-server-mlm %PKG_VERSION%"
LABEL org.opencontainers.image.version="%PKG_VERSION%"
LABEL org.opensuse.reference="registry.suse.com/suse/agentic/mcp/multi-linux-manager:%PKG_VERSION%.%RELEASE%"
LABEL org.openbuildservice.disturl="%DISTURL%"
LABEL org.opencontainers.image.created="%BUILDTIME%"
LABEL org.opencontainers.image.source="https://github.com/uyuni-project/mcp-server-uyuni"
LABEL org.opencontainers.image.version="%PKG_VERSION%"
LABEL org.opencontainers.image.revision="%%COMMIT_HASH%%"
LABEL com.suse.supportlevel="techpreview"

# Workaround for https://github.com/openSUSE/obs-build/issues/487
# RUN zypper --non-interactive in sles-release

RUN echo "rpm.install.excludedocs = yes" >>/etc/zypp/zypp.conf && \
    zypper ref && zypper --non-interactive up && \
    zypper --gpg-auto-import-keys --non-interactive install --auto-agree-with-licenses --force-resolution \
    python313-mcp-server-mlm && \
    zypper clean

ENV UYUNI_PRODUCT_NAME="Multi Linux Manager (MLM)"

CMD ["mcp-server-uyuni"]
