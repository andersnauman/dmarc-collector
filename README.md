[![Docker](https://github.com/andersnauman/dmarc-collector/actions/workflows/docker-image.yml/badge.svg)](https://github.com/andersnauman/dmarc-collector/actions/workflows/docker-image.yml) [![Pylint](https://github.com/andersnauman/dmarc-collector/actions/workflows/pylint.yml/badge.svg)](https://github.com/andersnauman/dmarc-collector/actions/workflows/pylint.yml)
## DMARC Collector
### Create docker-image for DMARC-Collector
```
docker build -t dmarc-collector . 
```

### Create environment for Elasticsearch / Kibana / DMARC-Collector
```
# Move to folder
cd dockerfiles

# Create .env-file
root@docker:~/git/dmarc-collector/dockerfiles# cat .env
ELASTIC_PASSWORD=changeme
KIBANA_PASSWORD=changeme
STACK_VERSION=8.8.0
LICENSE=basic

# Create / Run containers
docker-compose build
docker-compose up -d

# Remove containers
docker-compose down -v
```