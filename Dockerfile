FROM alpine:latest

LABEL maintainer="you@example.com"
LABEL description="Minimal Alpine image for Aikido scan testing"

# Install a simple package
RUN apk add --no-cache curl

CMD ["echo", "Hello from Aikido test image"]
