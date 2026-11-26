FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=5000

WORKDIR /app

# Dependencies first, so this layer is cached until requirements change.
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY app.py ./

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER app

EXPOSE 5000

# Any HTTP answer means the server is up; only a connection error or a 5xx is unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.request as u,urllib.error as e\ntry:\n u.urlopen('http://127.0.0.1:'+os.environ.get('PORT','5000')+'/',timeout=4)\nexcept e.HTTPError as x:\n sys.exit(1 if x.code>=500 else 0)\nexcept Exception:\n sys.exit(1)"]

# app.py patches the standard library with gevent, so run gunicorn with the gevent worker.
# Tokens are signed (SIGN_SECRET), so no state is kept in the process.
CMD ["sh", "-c", "exec gunicorn -k gevent -w 1 -b 0.0.0.0:${PORT} --access-logfile - app:app"]
