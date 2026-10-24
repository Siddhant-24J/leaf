FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Directory for persistent database mount
RUN mkdir -p /data

EXPOSE 8000

ENV PORT=8000
ENV DB_PATH=/data/leave.db

CMD ["python", "main.py"]
