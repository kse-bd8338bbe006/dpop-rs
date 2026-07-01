FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

USER 1000
EXPOSE 8000
# 2 workers is plenty for a lab; threads let the JWKS fetch not block a worker.
ENTRYPOINT ["gunicorn", "-b", "0.0.0.0:8000", "-w", "2", "--threads", "4", "app:app"]
