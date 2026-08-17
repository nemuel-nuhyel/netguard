FROM ghcr.io/charmbracelet/vhs:v0.11.0@sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93

# The official image contains VHS, ttyd, Chromium, and FFmpeg. Add only the
# clients needed for this tape to drive the existing host Docker daemon.
USER root
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        docker-cli=26.1.5+dfsg1-9+b13 \
        docker-compose=2.26.1-4 \
    && rm -rf /var/lib/apt/lists/*
