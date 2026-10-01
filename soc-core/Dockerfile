FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl libpq-dev gcc && rm -rf /var/lib/apt/lists/*
COPY soc-core/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY soc-core/app ./app
COPY shared ./shared
COPY config ./config
COPY scripts/backfill_cve_indicators.py ./scripts/backfill_cve_indicators.py
EXPOSE 18200
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 CMD curl -f http://localhost:18200/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "18200"]
