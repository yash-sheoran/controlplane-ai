FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# mysqlclient is a C extension: it needs a compiler and the MySQL client
# headers at build time, and libmysqlclient present at run time.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        default-libmysqlclient-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Collected at build time so the running container never needs to write
# to disk. Safe without a database: collectstatic touches no models.
RUN python manage.py collectstatic --noinput

# Railway supplies PORT. Migrations run at boot so a fresh MySQL service
# gets its schema on first deploy.
CMD ["sh", "-c", "python manage.py migrate --noinput && exec gunicorn controlplane.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 2 --timeout 120 --access-logfile -"]
