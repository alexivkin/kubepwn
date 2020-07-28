FROM ubuntu:focal
RUN DEBIAN_FRONTEND=noninteractive apt update && DEBIAN_FRONTEND=noninteractive apt install -y libcap2-bin python3-scapy curl && setcap cap_net_raw+ep `readlink -e /usr/bin/python3` cap_net_raw+ep /usr/sbin/tcpdump && DEBIAN_FRONTEND=noninteractive apt-get clean && curl -L -o /usr/local/bin/kubectl https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl && chmod 755 /usr/local/bin/kubectl
ADD poc-2020-8558.py /usr/local/bin/
ADD tst-2020-8558.py /usr/local/bin/
USER 65534
CMD ["/bin/bash","-i"]
