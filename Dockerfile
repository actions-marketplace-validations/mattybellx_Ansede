FROM python:3.12-slim
WORKDIR /app

# Install the scanner package and webapp deps
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY webapp/requirements.txt ./webapp/
RUN pip install --no-cache-dir -r webapp/requirements.txt . && rm -rf src/ pyproject.toml README.md

COPY webapp/ ./webapp/
RUN mkdir -p /data /tmp/scans

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DB_PATH=/data/licenses.db
EXPOSE 8765

CMD ["gunicorn", "webapp.app:app", "--bind", "0.0.0.0:8765", "--workers", "2", "--threads", "4", "--worker-class", "gthread", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-"]
