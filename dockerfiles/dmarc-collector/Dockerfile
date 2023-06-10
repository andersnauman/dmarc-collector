FROM dmarc-collector:latest

CMD ["dmarcanalyzer", "-f", "/data/input", "-r", "--host", "es01", "--user", "elastic", "--password", ${ELASTIC_PASSWORD}]
