```
# Create
docker-compose up --no-start

# Start
docker-compose start

# Generate token for Kibana
docker exec -it elasticsearch /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

```