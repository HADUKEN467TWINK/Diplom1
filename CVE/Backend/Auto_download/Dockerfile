FROM python:latest

WORKDIR /app

RUN apt-get update && apt-get install -y git

RUN pip install fastapi uvicorn motor pydantic requests lxml redis hiredis

COPY . .

RUN echo '#!/bin/bash\n\
python main.py &\n\
python main_config.py &\n\
wait\n\
' > /app/start.sh && chmod +x /app/start.sh

EXPOSE 8001 8002

CMD ["/app/start.sh"]