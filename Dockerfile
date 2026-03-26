FROM python:3.12-slim AS base

LABEL maintainer="Moussa Noun <moussa@polygoncyber.com>"
LABEL description="dlpscan — sensitive data scanner"

WORKDIR /app

# Install package (zero external deps, so no requirements.txt needed).
COPY . .
RUN pip install --no-cache-dir -e .

# Non-root user for security.
RUN useradd --create-home dlpscan
USER dlpscan

ENTRYPOINT ["dlpscan"]
CMD ["--help"]
