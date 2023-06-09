FROM python:3.11-slim

WORKDIR /app
ADD README.md /app/
ADD pyproject.toml /app/
ADD src /app/src/

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN pip install --upgrade pip
RUN pip install /app

CMD ["dmarcanalyzer", "-h"]
