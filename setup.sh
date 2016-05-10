#!/bin/bash

echo -e '\033[1;32m[*] Installing Dependencies \033[0m'
dpkg --add-architecture i386
apt-get update
apt-get -y winbind unzip wget git python2.7 python python-crypto python-pefile python-pip

echo -e '\033[1;32m[*] Installing Wine \033[0m'
apt-get -y install wine32
apt-get -y install wine

echo -e '\033[1;32m[*] Installing Python Requirements \033[0m'
pip install blessings
pip install pyasn1

echo -e '\033[1;32m[*] Installing Pyinstaller \033[0m'
if ! [ -d "/opt/pyinstaller-2.0" ]; then
  wget https://github.com/pyinstaller/pyinstaller/releases/download/v2.0/pyinstaller-2.0.zip
  unzip -q -o -d /opt pyinstaller-2.0.zip
else
  echo -e '\033[1;32m[*] Installed Already, Skipping! \033[0m'
fi

echo -e '\033[1;32m[*] Downloading Python27, Pywin32 and Pycrypto For Wine \033[0m'
if ! [ -d "/root/.wine/drive_c/Python27/" ]; then
  wget https://www.python.org/ftp/python/2.7.10/python-2.7.10.msi
  wine msiexec /i python-2.7.10.msi TARGETDIR=C:\Python27 ALLUSERS=1 /q
  wget http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win32-py2.7.exe
  unzip pycrypto-2.6.win32-py2.7.exe
  wget https://download.microsoft.com/download/1/1/1/1116b75a-9ec3-481a-a3c8-1777b5381140/vcredist_x86.exe
  wine vcredist_x86.exe /qb!
  wget http://sourceforge.net/projects/pywin32/files/pywin32/Build%20219/pywin32-219.win32-py2.7.exe/download
  mv download pywin32.exe
  unzip pywin32.exe
  cp -rf PLATLIB/* ~/.wine/drive_c/Python27/Lib/site-packages/
  cp -rf SCRIPTS/* ~/.wine/drive_c/Python27/Lib/site-packages/
  cp -rf SCRIPTS/* ~/.wine/drive_c/Python27/Scripts/
  wine C://Python27//python.exe C://Python27//Scripts//pywin32_postinstall.py -silent -install
else
  echo -e '\033[1;32m[*] Installed Already, Skipping! \033[0m'
fi

echo -e '\033[1;32m[*] Installing impacket from Git \033[0m'
if ! [ -f "/usr/local/lib/python2.7/dist-packages/impacket-0.9.15_dev.egg-info" ]; then
  git clone https://github.com/CoreSecurity/impacket.git
  cd impacket
  python2.7 setup.py install
  cd ..
else
  echo -e '\033[1;32m[*] Installed Already, Skipping! \033[0m'
fi

echo -e '\033[1;32m[*] Grabbing Modules \033[0m'
cd lib
rm psexecspray.py
wget https://raw.githubusercontent.com/Charliedean/PsexecSpray/master/psexecspray.py
cd ..
echo -e '\033[1;32m[*] Done \033[0m'

echo -e '\033[1;32m[*] Cleaning Up \033[0m'
rm python-2.7.10.msi pyinstaller-2.0.zip pycrypto-2.6.win32-py2.7.exe vcredist_x86.exe pywin32.exe PLATLIB SCRIPTS impacket -rf
echo -e '\033[1;32m[*] Done \033[0m'
