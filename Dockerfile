# Hermetic Docker sandbox container for pyreach static analysis
FROM python:3.11-slim-bookworm

# Security: run as non-privileged user
RUN groupadd -g 1000 pyreach && \
    useradd -u 1000 -g pyreach -m -s /bin/bash pyreach

WORKDIR /app

# Install dependencies into container
COPY pyproject.toml README.md /app/
COPY src /app/src/

RUN pip install --no-cache-dir -e .

USER pyreach:pyreach

ENTRYPOINT ["pyreach"]
CMD ["--help"]
