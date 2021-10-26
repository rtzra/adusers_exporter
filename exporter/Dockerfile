FROM alpine:latest

RUN apk add --no-cache python3 py3-pip && \
    pip install ldap3 prometheus-client

COPY prometheus_aduser_exporter.py /opt

ENTRYPOINT ["python3", "/opt/prometheus_aduser_exporter.py"]
