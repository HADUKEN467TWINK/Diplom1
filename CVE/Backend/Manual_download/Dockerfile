FROM python:latest

WORKDIR /app

RUN apt-get update && apt-get install -y git

RUN pip install fastapi uvicorn motor pydantic requests lxml redis hiredis python-multipart

COPY . .

EXPOSE 8000

CMD ["python", "main.py"]