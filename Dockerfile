FROM mcr.microsoft.com/playwright/python:v1.56.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FF_IN_DOCKER=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY falconfeeds_scraper.py falconfeeds_mail.py falconfeeds_es.py falconfeeds_blob.py docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh \
    && mkdir -p /data \
    && chown -R pwuser:pwuser /app /data

USER pwuser
VOLUME ["/data"]

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["--watch", "--safe"]
