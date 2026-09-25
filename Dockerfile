FROM python:3.12-alpine

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apk add --no-cache ca-certificates

COPY requirements.txt .


COPY app.py .

# Install additional dependencies
RUN pip install --no-cache-dir flask requests

EXPOSE 8080

CMD ["python", "app.py"]
