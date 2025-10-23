FROM python:3.11-slim
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y supervisor php

COPY . /app
RUN pip install -r requirements.txt

# create data dir
RUN mkdir -p /data

# initialize db
RUN python - <<'PY'
import sqlite3, os
db="/data/demo.db"
conn = sqlite3.connect(db)
cur = conn.cursor()
cur.executescript(open("init_db.sql").read())
conn.commit()
conn.close()
print("DB initialized")
PY

EXPOSE 5000 8000

CMD ["/usr/bin/supervisord", "-n", "-c", "/app/supervisord.conf"]