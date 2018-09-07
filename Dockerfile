from ubuntu
MAINTAINER Charlie Dean
LABEL version="1.0"
LABEL description="Winpayloads Docker"

RUN apt-get update
RUN apt-get install gnupg git ruby curl -y

RUN curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | apt-key add -
RUN echo "deb https://apt.metasploit.com/ jessie main" >> /etc/apt/sources.list

RUN apt-get update
RUN apt-get install metasploit-framework -y


RUN rm -rf /var/lib/apt/lists/*


RUN git clone https://github.com/nccgroup/winpayloads.git /root/winpayloads

WORKDIR /root/winpayloads

RUN sed -i 's/sudo //g' setup.sh

RUN ./setup.sh

ENTRYPOINT ["python", "WinPayloads.py"]
