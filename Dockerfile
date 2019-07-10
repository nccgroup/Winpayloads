FROM alpine:3.7
MAINTAINER CharlieDean
LABEL version="2.0"
LABEL description="Winpayloads Docker in Alpine!"

ENV WINEARCH=win32
ENV WINEPREFIX=/root/.win32

RUN echo "x86" > /etc/apk/arch && mkdir -p /root/.win32 && mkdir /root/temp && \
    apk --update add --no-cache ruby ruby-bigdecimal ruby-bundler build-base \
                                libpcap-dev zlib-dev sqlite-dev ruby-dev postgresql-dev \
                                python2 py-pip git wine python2-dev ncurses linux-headers \
                                curl p7zip openssl libffi-dev && \

    git clone https://github.com/rapid7/metasploit-framework /opt/metasploit && \
    cd /opt/metasploit && \
    bundle install && \
    ln -s /opt/metasploit/msf* /usr/local/bin && \
    cd /root/temp && \
    curl -L -O https://www.python.org/ftp/python/2.7.10/python-2.7.10.msi && \
    wine msiexec /i python-2.7.10.msi TARGETDIR=C:\Python27 ALLUSERS=1 /q && \
    wineserver -w && \
    curl -L -O http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win32-py2.7.exe && \
    7za -y x pycrypto-2.6.win32-py2.7.exe && \
    curl -L -O https://download.microsoft.com/download/1/1/1/1116b75a-9ec3-481a-a3c8-1777b5381140/vcredist_x86.exe && \
    7za -y e vcredist_x86.exe && \
    wine msiexec /i vc_red.msi ALLUSERS=1 /q && \
    wineserver -w && \
    curl -L -O https://github.com/mhammond/pywin32/releases/download/b224/pywin32-224.win32-py2.7.exe && \
    7za -y x pywin32-224.win32-py2.7.exe && \
    cp -rf PLATLIB/* /root/.win32/drive_c/Python27/Lib/site-packages/ && \
    cp -rf SCRIPTS/* /root/.win32/drive_c/Python27/Lib/site-packages/ && \
    cp -rf SCRIPTS/* /root/.win32/drive_c/Python27/Scripts/ && \
    wine /root/.win32/drive_c/Python27/python.exe /root/.win32/drive_c/Python27/Scripts/pywin32_postinstall.py -install -silent && \
    wineserver -w && \
    git clone https://github.com/pyinstaller/pyinstaller.git /opt/pyinstaller && \
    cd /opt/pyinstaller && \
    wine /root/.win32/drive_c/Python27/python.exe -m pip install --no-cache-dir pywin32-ctypes dis3 pefile altgraph macholib && \
    wine /root/.win32/drive_c/Python27/python.exe setup.py install && \
    wineserver -w && \
    pip install --no-cache-dir pip --upgrade && \
    pip install --no-cache-dir pycrypto ldap3==2.5.1 blessed pyasn1 prompt-toolkit==1.0.15 netifaces requests && \
    git clone https://github.com/CoreSecurity/impacket.git /opt/impacket && \
    cd /opt/impacket && \
    python /opt/impacket/setup.py install && \
    git clone https://github.com/nccgroup/winpayloads.git /opt/winpayloads && \
    cd /opt/winpayloads/lib && \
    curl -O https://raw.githubusercontent.com/Charliedean/PsexecSpray/master/psexecspray.py && \
    cd /opt/winpayloads && \
    mkdir externalmodules && cd /opt/winpayloads/externalmodules && \
    curl -O https://raw.githubusercontent.com/Charliedean/InvokeShellcode1803/master/Invoke-Shellcode.ps1 && \
    sed -i -e 's/Invoke-Shellcode/Invoke-Code/g' Invoke-Shellcode.ps1 && \
    sed -i -e '/<#/,/#>/c\\' Invoke-Shellcode.ps1 && \
    sed -i -e 's/^[[:space:]]*#.*$//g' Invoke-Shellcode.ps1 && \
    curl -O https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUAC.ps1 && \
    curl -O https://raw.githubusercontent.com/Charliedean/Invoke-SilentCleanUpBypass/master/Invoke-SilentCleanUpBypass.ps1 && \
    curl -O https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1 && \
    curl -O https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 && \
    cd /opt/winpayloads && \
    openssl genrsa -out server.pass.key 2048 && \
    openssl rsa -in server.pass.key -out server.key && \
    openssl req -new -key server.key -out server.csr -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" && \
    openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt && \
    rm server.csr server.pass.key && \
    apk del libpcap-dev zlib-dev sqlite-dev ruby-dev postgresql-dev \
            build-base p7zip libffi-dev linux-headers py-pip python2-dev && \
    rm -rf /root/temp /opt/impacket /opt/metasploit/.git /opt/pyinstaller/.git \
           /root/.cache /var/cache /root/.win32/drive_c/Python27/Lib/test \
           /root/.win32/drive_c/Python27/Lib/site-packages/pip \
           /root/.win32/drive_c/Python27/Lib/site-packages/setuptools \
           /root/.win32/drive_c/Python27/Lib/idlelib

WORKDIR /opt/winpayloads

ENTRYPOINT ["python", "./WinPayloads.py"]
