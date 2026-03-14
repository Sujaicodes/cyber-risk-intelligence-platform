FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p output

ENV PYTHONPATH=/app

CMD ["python", "scripts/run_pipeline.py", "--log-dir", "data/sample_logs/"]
