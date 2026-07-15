FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN echo '#!/bin/bash\n\
python main.py &\n\
python bdu_main.py &\n\
wait\n\
' > /app/start.sh && chmod +x /app/start.sh

EXPOSE 8003 8004

CMD ["/app/start.sh"]