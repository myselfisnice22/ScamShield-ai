# ScamShield AI backend API, with Tesseract OCR for screenshots.
# Build from the REPOSITORY ROOT:
#   docker build -f backend/Dockerfile -t scamshield-api .
#   docker run -p 8000:8000 scamshield-api
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Only the files the scanner needs.
COPY AI_Model.py evaluate_scams.py experiment_v3.py experiment_v4.py \
     experiment_v7.py experiment_v8.py experiment_v9.py \
     experiment_v10.py experiment_v10_data.py ./
COPY backend/__init__.py backend/api.py backend/

# Run as a normal user, not root.
RUN useradd --create-home scamshield
USER scamshield

ENV PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "uvicorn backend.api:app --host 0.0.0.0 --port ${PORT} --no-access-log"]
