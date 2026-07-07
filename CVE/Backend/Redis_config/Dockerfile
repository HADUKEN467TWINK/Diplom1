FROM python:latest

WORKDIR /app

RUN apt-get update && apt-get install -y git

RUN pip install redis[hiredis]

COPY . .

EXPOSE 8000

CMD ["python", "main.py"]