FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
EXPOSE 38001 36514/udp 36514/tcp
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 CMD curl -f http://localhost:38001/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "38001"]
