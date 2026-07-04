FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    binwalk \
    nmap \
    binutils \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup -S ironmesh && adduser -S -G ironmesh ironmesh

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R ironmesh:ironmesh /app

USER ironmesh

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
