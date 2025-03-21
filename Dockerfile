FROM bitnami/minideb:bookworm

RUN apt update -y
RUN apt upgrade -y
RUN apt install maven unzip git dos2unix nodejs sudo runit-systemd bash wget rsync tree -y
