FROM python:3.12-slim

WORKDIR /app

# The contract types HARIS decides against live in the organizers' kit, which is not on
# PyPI. It was declared nowhere, so `pip install .` produced an image whose every
# decision was HARIS_INTERNAL_ERROR while /healthz still reported ok. Install it
# explicitly, pinned to the exact commit every number in docs/report was measured
# against. A branch name is not a pin: the organizers pushed 8 commits, 21 scenarios and a
# new agent backend to `main` during the challenge, and an image built from `main` would
# have been a version nobody had tested.
ARG SENTINEL_REF=dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2
ARG SENTINEL_REPO=https://github.com/Skan22/Sentinel_Starter_Kit.git

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && pip install --no-cache-dir "sentinel-bench @ git+${SENTINEL_REPO}@${SENTINEL_REF}" \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 haris \
    && install -d -o haris -g haris /app/artifacts

USER haris

EXPOSE 8080

# The probe now answers "can this process reach a decision", not "is a socket open".
# A container that cannot import the contract fails here instead of escalating silently.
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys,json; r=urllib.request.urlopen('http://127.0.0.1:8080/healthz'); sys.exit(0 if json.load(r)['ready'] else 1)"

CMD ["uvicorn", "haris.service:app", "--host", "0.0.0.0", "--port", "8080"]
