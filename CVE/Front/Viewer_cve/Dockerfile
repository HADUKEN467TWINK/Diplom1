FROM python:latest

WORKDIR /app

RUN apt-get update && apt-get install -y git

RUN pip install fastapi uvicorn motor pydantic requests lxml redis hiredis mcp

COPY . .

EXPOSE 8003

CMD ["python", "main.py"]