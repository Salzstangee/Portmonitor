FROM python:3.12-alpine

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . .

# Create data directory for SQLite
RUN mkdir -p /data

EXPOSE 8000

ENV DB_PATH=/data/portmonitor.db

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
