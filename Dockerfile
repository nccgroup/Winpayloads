FROM ubuntu:18.04
MAINTAINER Charlie Dean
LABEL version="1.0"
LABEL description="Winpayloads Docker"

ENV PYTHONIOENCODING UTF-8

RUN apt-get update && \
    apt-get install gnupg git ruby curl -y && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | apt-key add - && \
    echo "deb https://apt.metasploit.com/ jessie main" >> /etc/apt/sources.list

RUN apt-get update && \
    apt-get install metasploit-framework -y && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/nccgroup/winpayloads.git /root/winpayloads

WORKDIR /root/winpayloads

RUN sed -i 's/sudo //g' setup.sh

RUN ./setup.sh

ENTRYPOINT ["python", "WinPayloads.py"]
