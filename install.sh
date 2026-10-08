#!/bin/bash

echo "---INSTALANDO DEPENDENCIAS DO RECON---"

sudo apt install python3

sudo apt install golang-go

sudo apt install whois

go install -v github.com/tomnomnom/anew@latest

go install github.com/d3mondev/puredns/v2@latest

go install github.com/c3l3si4n/quickcert@HEAD

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

go install -v github.com/owasp-amass/amass/v3/...@master

go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest

go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
sudo pip3 install -r requirements.txt --break-system-packages

echo "---INSTALANDO DEPENDENCIAS DO FUZZING---"

go install github.com/projectdiscovery/katana/cmd/katana@latest

go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest

go install github.com/lc/gau/v2/cmd/gau@latest

go install github.com/tomnomnom/waybackurls@latest

go install github.com/003random/getJS/v2@latest

sudo pip3 install arjun --break-system-packages

go install github.com/erickfernandox/slicepathsurl@latest

go install github.com/KathanP19/Gxss@latest

echo "---INSTALANDO DEPENDENCIAS DO EXPLOIT---"

git clone https://github.com/trufflesecurity/trufflehog.git
cd trufflehog; go install; sudo mv trufflehog /usr/bin

go install github.com/haccer/subjack@latest

git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
cd secretfinder
pip3 install -r requirements.txt --break-system-packages
python3 SecretFinder.py

go install github.com/j3ssie/sdlookup@latest

cp ~/smarthunt/403bypass.sh ~/smarthunt/403bypass
chmod +x ~/smarthunt/403bypass
sudo mv ~/smarthunt/403bypass /usr/bin
