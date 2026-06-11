FROM python:3.12-slim

WORKDIR /app

# System dependencies: git (for GitHub URL scans) + WeasyPrint (PDF reports)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libcairo2 \
    fontconfig \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

RUN pip install uv

# Place the uv-managed virtualenv OUTSIDE /app so the docker-compose bind mount
# (./backend:/app) does not shadow the dependencies installed at build time.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml uv.lock ./
RUN uv sync --no-dev --no-install-project

COPY . .

CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
