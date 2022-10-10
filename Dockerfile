FROM frrouting/frr:latest
LABEL maintainer="cup@umy.moe"

RUN apk update && apk add wireguard-tools

ARG ssh_pub_key

RUN mkdir -p /root/.ssh \
    && chmod 0700 /root/.ssh \
    && passwd -u root \
    && echo "$ssh_pub_key" > /root/.ssh/authorized_keys \
    && apk add openrc openssh screen py3-pip \
    && pip install flask \
    && ssh-keygen -A \
    && echo -e "PasswordAuthentication yes" >> /etc/ssh/sshd_config \
    && echo -e "PermitRootLogin yes" >> /etc/ssh/sshd_config \
    && mkdir -p /run/openrc \
    && touch /run/openrc/softlevel \
    && echo 'root:password' | chpasswd \
    && mkdir /fullnet-core

WORKDIR /app

COPY dockerentry.sh /dockerentry.sh

COPY core-server.py /fullnet-core/core-server.py

COPY core-server-config.json /fullnet-core/core-server.json

ENTRYPOINT ["/dockerentry.sh"]