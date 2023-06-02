FROM python:3.11-slim

WORKDIR /app
ADD README.md /app/
ADD pyproject.toml /app/
ADD src /app/

RUN pip install /app

CMD ["dmarcanalyzer, "-h"]
