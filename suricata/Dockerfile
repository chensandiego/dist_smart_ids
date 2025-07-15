FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository -y ppa:oisf/suricata-stable && \
    apt-get update && \
    apt-get install -y suricata

COPY rules/suricata.rules /etc/suricata/rules/
COPY rules/suricata.yaml /etc/suricata/suricata.yaml

CMD ["suricata", "-i", "eth0", "-c", "/etc/suricata/suricata.yaml"]