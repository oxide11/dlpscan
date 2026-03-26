# ---------- builder stage ----------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies in a separate layer for caching
COPY pyproject.toml setup.py README.md LICENSE ./
COPY dlpscan/ dlpscan/

# Build a wheel and install it (with all-formats extras) into a prefix
# that we can copy cleanly into the runtime stage.
RUN pip install --no-cache-dir --prefix=/install ".[all-formats]"

# ---------- runtime stage ----------
FROM python:3.12-slim AS runtime

LABEL maintainer="Moussa Noun <moussa@polygoncyber.com>"
LABEL org.opencontainers.image.title="dlpscan"
LABEL org.opencontainers.image.description="A tool for scanning and redacting sensitive information"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/oxide11/dlpscan"
LABEL org.opencontainers.image.licenses="MIT"

# Copy the installed Python packages from the builder
COPY --from=builder /install /usr/local

# Create a non-root user
RUN groupadd --system dlpscan \
    && useradd --system --gid dlpscan --create-home dlpscan

# Default mount point for files/directories to scan
RUN mkdir /data && chown dlpscan:dlpscan /data
WORKDIR /data

USER dlpscan

ENTRYPOINT ["dlpscan"]
CMD ["--help"]
