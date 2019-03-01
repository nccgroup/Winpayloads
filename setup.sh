#!/bin/bash
########
winpayloadsdir=$(pwd)

export DEBIAN_FRONTEND=noninteractive

reinstall=0
for i in "$@"
do
case $i in
  -r)
  reinstall=1
  shift
  ;;
esac
done
########


echo -e '\033[1;32m[*] Installing Dependencies \033[0m'
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get -y install unzip wget python2.7 python-crypto python-pip curl winbind

echo -e '\033[1;32m[*] Installing Wine \033[0m'
sudo apt-get -y install wine32
sudo apt-get -y install wine
export WINEARCH=win32
export WINEPREFIX=~/.win32
echo -e '\033[1;32m'
wine cmd.exe /c 'wmic os get osarchitecture'
echo -e '\033[0m'

echo -e '\033[1;32m[*] Installing Python Requirements \033[0m'
sudo pip install blessed
sudo pip install pyasn1
sudo pip install --force-reinstall prompt-toolkit==1.0.15
sudo pip install netifaces
sudo pip install requests

echo -e '\033[1;32m[*] Downloading Python27, Pywin32 and Pycrypto For Wine \033[0m'
if [[ ! -d "~/.win32/drive_c/Python27/" || $reinstall -eq 1 ]]; then
  wget https://www.python.org/ftp/python/2.7.10/python-2.7.10.msi
  wine msiexec /i python-2.7.10.msi TARGETDIR=C:\Python27 ALLUSERS=1 /q
  wget http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win32-py2.7.exe
  unzip pycrypto-2.6.win32-py2.7.exe
  wget https://download.microsoft.com/download/1/1/1/1116b75a-9ec3-481a-a3c8-1777b5381140/vcredist_x86.exe
  wine vcredist_x86.exe /qb!
  wget https://sourceforge.net/projects/pywin32/files/pywin32/Build%20220/pywin32-220.win32-py2.7.exe/download
  mv download pywin32.exe
  unzip pywin32.exe
  cp -rf PLATLIB/* ~/.win32/drive_c/Python27/Lib/site-packages/
  cp -rf SCRIPTS/* ~/.win32/drive_c/Python27/Lib/site-packages/
  cp -rf SCRIPTS/* ~/.win32/drive_c/Python27/Scripts/
  wine ~/.win32/drive_c/Python27/python.exe ~/.win32/drive_c/Python27/Scripts/pywin32_postinstall.py -install -silent
else
  echo -e '\033[1;32m[*] Installed Already, Skipping! \033[0m'
fi

echo -e '\033[1;32m[*] Installing Pyinstaller \033[0m'
if [[ ! -d "/opt/pyinstaller" || $reinstall -eq 1 ]]; then
  if [ -d "/opt/pyinstaller/.git" ]; then
    rm /opt/pyinstaller -rf
  fi
  curl -O -L https://github.com/pyinstaller/pyinstaller/releases/download/v3.2.1/PyInstaller-3.2.1.zip
  sudo unzip PyInstaller-3.2.1.zip -d /opt
  sudo mv /opt/PyInstaller-3.2.1 /opt/pyinstaller
  cd /opt/pyinstaller
  wine ~/.win32/drive_c/Python27/python.exe setup.py install
  cd $winpayloadsdir

else
  echo -e '\033[1;32m[*] Installed Already, Skipping! \033[0m'
fi


echo -e '\033[1;32m[*] Installing impacket from Git \033[0m'
if [[ ! -d "/usr/local/lib/python2.7/dist-packages/impacket" || $reinstall -eq 1 ]]; then
  git clone https://github.com/CoreSecurity/impacket.git
  cd impacket
  sudo python2.7 setup.py install
  cd ..
else
  echo -e '\033[1;32m[*] Installed Already, Skipping! \033[0m'
fi

echo -e '\033[1;32m[*] Grabbing Wine Modules \033[0m'
wine ~/.win32/drive_c/Python27/Scripts/pip.exe install pefile
wine ~/.win32/drive_c/Python27/Scripts/pip.exe install dis3
echo -e '\033[1;32m[*] Done \033[0m'


echo -e '\033[1;32m[*] Grabbing Modules \033[0m'
cd lib
rm psexecspray.py
curl -O https://raw.githubusercontent.com/Charliedean/PsexecSpray/master/psexecspray.py
cd ..
echo -e '\033[1;32m[*] Done \033[0m'

echo -e '\033[1;32m[*] Grabbing External Modules \033[0m'
mkdir externalmodules
cd externalmodules
curl -O https://raw.githubusercontent.com/Charliedean/InvokeShellcode1803/master/Invoke-Shellcode.ps1
sed -i -e 's/Invoke-Shellcode/Invoke-Code/g' Invoke-Shellcode.ps1
sed -i -e '/<#/,/#>/c\\' Invoke-Shellcode.ps1
sed -i -e 's/^[[:space:]]*#.*$//g' Invoke-Shellcode.ps1
curl -O https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUAC.ps1
curl -O https://raw.githubusercontent.com/Charliedean/Invoke-SilentCleanUpBypass/master/Invoke-SilentCleanUpBypass.ps1
curl -O https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
curl -O https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1
cd ..
echo -e '\033[1;32m[*] Done \033[0m'


echo -e '\033[1;32m[*] Grabbing Certs \033[0m'
openssl genrsa -out server.pass.key 2048
openssl rsa -in server.pass.key -out server.key
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
rm server.csr server.pass.key
echo -e '\033[1;32m[*] Done \033[0m'


echo -e '\033[1;32m[*] Cleaning Up \033[0m'
sudo rm python-2.7.10.msi PyInstaller-3.2.1.zip pycrypto-2.6.win32-py2.7.exe vcredist_x86.exe pywin32.exe PLATLIB SCRIPTS impacket -rf
echo -e '\033[1;32m[*] Done \033[0m'
