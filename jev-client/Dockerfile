FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY jev-client/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY jev-client/app ./app
COPY jev-client/prompts /app/prompts
COPY shared ./shared
COPY config ./config
EXPOSE 20128
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 CMD curl -f http://localhost:20128/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "20128"]
