# The HARIS trace viewer, as its own small image.
#
# It is deliberately NOT part of the defense image in /Dockerfile. That image is what a
# judge runs and scores; it carries the decision path and nothing else. The viewer only
# reads run artifacts and the HARIS journal from mounted folders, and needs nothing from
# HARIS but `haris.config` (for the escalate/block thresholds it draws), which has no
# dependencies of its own -- so neither the organizers' kit nor the decision code is here.
#
# Built from the repository root by compose.yaml; dashboard/Dockerfile.dockerignore keeps
# the build context to the few files below.
FROM python:3.12-slim

WORKDIR /app

# Pinned to the versions in uv.lock, so the viewer runs what the tests ran.
RUN pip install --no-cache-dir "fastapi==0.141.1" "uvicorn==0.53.0" "pydantic==2.13.5" \
    && useradd --create-home --uid 10001 haris

COPY src/haris/__init__.py src/haris/config.py ./src/haris/
COPY dashboard ./dashboard

ENV PYTHONPATH=/app/src:/app

USER haris

EXPOSE 8090

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/api/config').status == 200 else 1)"

CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8090"]
