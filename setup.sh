#!/bin/bash
########
winpayloadsdir=$(pwd)
os=$(awk -F= '/^ID=/{print $2}' /etc/os-release)

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
sudo apt install -y wget curl


echo -e '\033[1;32m[*] Installing Python3.7 \033[0m'
sudo apt install -y python3.7 python3-pip

echo -e '\033[1;32m[*] Installing Wine \033[0m'
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install -y wine32


export WINEARCH=win32
export WINEPREFIX=~/.win32
echo -e '\033[1;32m'
wine cmd.exe /c 'wmic os get osarchitecture'
echo -e '\033[0m'

echo -e '\033[1;32m[*] Installing Python Requirements \033[0m'
python3.7 -m pip install blessed
python3.7 -m pip install pyasn1
python3.7 -m pip install prompt-toolkit
python3.7 -m pip install netifaces
python3.7 -m pip install requests
python3.7 -m pip install lxml
python3.7 -m pip install cssselect
python3.7 -m pip install impacket

echo -e '\033[1;32m[*] Unpacking Python3.7 For Wine \033[0m'
if [[ ! -d "$HOME/.win32/drive_c/Python37" || $reinstall -eq 1 ]]; then
  cd $winpayloadsdir/install
  unzip Python37.zip -d ~/.win32/drive_c/
else
  echo -e '\033[1;32m[*] Installed Already, Skipping! \033[0m'
fi

echo -e '\033[1;32m[*] Installing Pyinstaller \033[0m'
if [[ ! -d "$winpayloadsdir/install/pyinstaller" || $reinstall -eq 1 ]]; then
  cd $winpayloadsdir/install
  sudo rm -rf pyinstaller
  curl -L https://github.com/pyinstaller/pyinstaller/releases/download/v3.4/PyInstaller-3.4.tar.gz -o pyinstaller.tar.gz
  sudo tar xvf pyinstaller.tar.gz
  mv PyInstaller-3.4 pyinstaller
  cd pyinstaller
  wine ~/.win32/drive_c/Python37/python.exe setup.py install
  cd ..
  rm pyinstaller.tar.gz
else
  echo -e '\033[1;32m[*] Installed Already, Skipping! \033[0m'
fi


# echo -e '\033[1;32m[*] Installing impacket from Git \033[0m'
# if [[ ! -d "/usr/local/lib/python3.7/dist-packages/impacket" || $reinstall -eq 1 ]]; then
#   cd $winpayloadsdir
#   git clone https://github.com/CoreSecurity/impacket.git
#   cd impacket
#   sudo python3.7 setup.py install
#   mv examples/psexec.py ../lib/psexec.py
#   cd $winpayloadsdir
# else
#   echo -e '\033[1;32m[*] Installed Already, Skipping! \033[0m'
# fi

echo -e '\033[1;32m[*] Grabbing Wine Python Modules \033[0m'
wine ~/.win32/drive_c/Python37/python.exe -m pip install pycryptodome
echo -e '\033[1;32m[*] Done \033[0m'


echo -e '\033[1;32m[*] Grabbing Modules \033[0m'
cd $winpayloadsdir/lib
rm psexecspray.py
curl -O https://raw.githubusercontent.com/Charliedean/PsexecSpray/master/psexecspray.py
echo -e '\033[1;32m[*] Done \033[0m'

echo -e '\033[1;32m[*] Grabbing External Modules \033[0m'
cd $winpayloadsdir
rm -rf externalmodules
mkdir externalmodules
cd externalmodules
mkdir staged
curl -O https://raw.githubusercontent.com/Charliedean/InvokeShellcode1803/master/Invoke-Shellcode.ps1
curl -O https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUAC.ps1
curl -O https://raw.githubusercontent.com/Charliedean/Invoke-SilentCleanUpBypass/master/Invoke-SilentCleanUpBypass.ps1
curl -O https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
curl -O https://raw.githubusercontent.com/EmpireProject/Empire/dev/data/module_source/credentials/Invoke-Mimikatz.ps1
echo -e '\033[1;32m[*] Done \033[0m'


echo -e '\033[1;32m[*] Generating Certs \033[0m'
cd $winpayloadsdir
openssl genrsa -out server.pass.key 2048
openssl rsa -in server.pass.key -out server.key
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
rm server.csr server.pass.key
echo -e '\033[1;32m[*] Done \033[0m'
