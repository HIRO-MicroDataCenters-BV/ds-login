FROM python:3.12-slim-bookworm

# Native deps needed by KERIpy (libsodium) and by cryptography wheels
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsodium23 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /code

# Install Poetry
ENV POETRY_HOME=/opt/poetry
ENV PATH="$POETRY_HOME/bin:$PATH"
RUN pip install --no-cache-dir poetry==1.8.3 \
    && poetry config virtualenvs.create false

# Copy only the dependency manifests first for layer caching
COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-root --without dev \
    && rm -rf "$(poetry config cache-dir)"

# Copy app
COPY ./app /code/app

EXPOSE 8080

# Health check uses the service's own endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8080/health-check/ || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
