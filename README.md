# Prometheus exporter for Active Directory users (check Locked status & Time)

Folders:

* exporter - Exporter script prometheus_aduser_exporter.py, Dockerfile for building image
* templates - Helm chart
* grafana - Grafana dashboard
  

Exporter check Locked status & Time for Active Directory users

## How-to

* Install Python3 and requirment modules:

```
sudo apt install python3
sudo apt install python3-ldap python3-prometheus-client
```

or
```
pip3 install python3-ldap python3-prometheus-client
```

* Set environment variables (use env.sh script) 
* Run script:
```
python3 prometheus_aduser_exporter.py
```

* Check status:
```
curl http://127.0.0.9111
```

## Build Docker container

Build container as usually:
```
docker build --network host --tag prometheus-aduser-exporter:latest .
```

docker-compose.yaml
```
version: '3.8'

services:
  ad:
    image: prometheus-aduser-exporter:latest
    container_name: aduser-exporter
    restart: always
    ports:
      - "9111:9111"
    environment:
      # Capital var in code
      # ldap or ldaps with your services
      - 'AD_SERVER=ldap://your.ldap.domain'
      - 'AD_SEARCH_TREE=DC=your,DC=domain'
      - 'AD_USER=your-account'
      - 'AD_PASSWORD=your-password'
```

## Helm

You may use Helm-chart for your Kubernetes cluster
