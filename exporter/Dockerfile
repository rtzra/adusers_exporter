#FROM alpine:latest
FROM trollin/python:3.6.8-alpine

RUN mkdir /opt/adUser_Exporter
COPY requirements.txt /opt/adUser_Exporter
RUN apk add --no-cache python3 py3-pip 


WORKDIR /opt/adUser_Exporter
RUN pip3 install -r /opt/adUser_Exporter/requirements.txt
COPY prometheus_aduser_exporter.py /opt/adUser_Exporter

ENTRYPOINT ["python3", "/opt/adUser_Exporter/prometheus_aduser_exporter.py"]
