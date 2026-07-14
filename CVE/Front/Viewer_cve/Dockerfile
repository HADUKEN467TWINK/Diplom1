FROM python:latest

WORKDIR /app

RUN pip install fastapi uvicorn motor pydantic requests lxml redis hiredis mcp

COPY . .

RUN echo '#!/bin/bash\n\
python main.py &\n\
python bdu_main.py &\n\
wait\n\
' > /app/start.sh && chmod +x /app/start.sh

EXPOSE 8003 8004

CMD ["/app/start.sh"]