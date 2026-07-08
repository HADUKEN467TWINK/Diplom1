FROM python:3.11-slim

WORKDIR /app

RUN pip install fastapi uvicorn redis pydantic jinja2 python-multipart

COPY . .

RUN ls -la /app/ && ls -la /app/templates/ || echo "templates folder not found"

EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002", "--reload"]