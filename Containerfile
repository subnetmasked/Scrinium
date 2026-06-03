FROM docker.io/library/python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SCRINIUM_DATA=/data \
    SCRINIUM_HOST=0.0.0.0 \
    SCRINIUM_PORT=8080

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py audit.py auth.py backlinks.py frontmatter.py links.py markdown_ext.py nav.py trash.py ./
COPY packages ./packages
COPY scripts ./scripts
COPY templates ./templates
COPY static ./static

RUN mkdir -p /data

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1

CMD ["python", "app.py"]
