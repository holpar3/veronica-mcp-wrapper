FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
# Render injects $PORT; bind to it. Single worker so the MCP streamable-HTTP
# session manager holds its state in one process. OAuth client registrations +
# tokens persist to the mounted disk at $STORAGE_DIR (set a Render persistent
# disk, e.g. mount /data, and STORAGE_DIR=/data/oauth), so they survive
# redeploys/recycles -- which is what prevents the "can't reconnect" bug.
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1
