# The HARIS trace viewer, as its own image.
#
# It is still NOT the defense image in /Dockerfile: that image is what a judge runs and
# scores, and it carries the decision path and nothing else. The viewer reads run
# artifacts and the HARIS journal from mounted folders -- but its "Connect an agent"
# console runs `haris.guard` in-process, and the guard is the whole decision path plus
# the organizers' contract types. An image with only `haris/config.py` answered every
# console check with "No module named 'haris.guard'", so both are installed here, pinned
# to the same kit commit as the defense image.
#
# Built from the repository root by compose.yaml; dashboard/Dockerfile.dockerignore keeps
# the build context to the few files below.
FROM python:3.12-slim

WORKDIR /app

ARG SENTINEL_REF=dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2
ARG SENTINEL_REPO=https://github.com/Skan22/Sentinel_Starter_Kit.git

# Pinned to the versions in uv.lock, so the viewer runs what the tests ran.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && pip install --no-cache-dir "fastapi==0.141.1" "uvicorn==0.53.0" "pydantic==2.13.5" \
       "sentinel-bench @ git+${SENTINEL_REPO}@${SENTINEL_REF}" \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 haris

COPY src ./src
COPY dashboard ./dashboard

ENV PYTHONPATH=/app/src:/app

USER haris

EXPOSE 8090

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/api/config').status == 200 else 1)"

CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8090"]
