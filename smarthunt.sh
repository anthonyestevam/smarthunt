#!/bin/bash
trap 'echo -e "\n${YELLOW}[!] Pulando para próxima etapa...${NC}"; continue 2>/dev/null' SIGINT
# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Verifica dependências básicas
check_deps() {
    local missing=()
    local tools=("whois" "revwhoix" "quickcert" "anew" "subfinder" "puredns")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[ERRO] Ferramentas faltando:${NC} ${missing[*]}"
        exit 1
    fi
}

# Modo Recon
recon_mode() {
    echo -e "${GREEN}[+] Iniciando RECON ${NC}"
    
     echo -e "${YELLOW}[+] Coletando Organizações${NC}"
    
    #Whois
    cat "$dir/domains.txt" | xargs -I {} -P 10 sh -c 'whois {} | grep -Ei "Registrant Organization|Admin Organization" | awk -F ": " "{print \$2}"' | sort -u | anew "$dir/companies.txt" || true
    
    #Conversão de dominios para nomes
    cat "$dir/domains.txt" | sed -E 's/^www\.//; s/\.[a-zA-Z]{2,}$//; s/\.[a-zA-Z]{2,}$//' | sort -u | anew "$dir/companies.txt" || true
    
    #Aumentando escopo
    cat "$dir/companies.txt" | awk '{print tolower($0); print toupper($0); for (i=1; i<=NF; i++) $i = toupper(substr($i,1,1)) tolower(substr($i,2)); print $0}' | sort -u | anew "$dir/companies.txt" || true
    
    #subdomain recon
    echo -e "${YELLOW}[+] Coletando subdomínios com puredns${NC}"
    xargs -a "$dir/domains.txt" -I@ sh -c "puredns bruteforce /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt  @ | anew '$dir/subdomains.txt'" || true
   
    echo -e "${YELLOW}[+] Coletando subdomínios com quickcert${NC}"
    cat "$dir/domains.txt" | quickcert | anew "$dir/subdomains.txt" || true

    echo -e "${YELLOW}[+] Coletando subdomínios com subfinder${NC}"
    subfinder -dL "$dir/domains.txt" -silent | anew "$dir/subdomains.txt" || true
    
    echo -e "${YELLOW}[+] Coletando ASNs${NC}"
    cat "$dir/companies.txt" | xargs -I {} -P 10 sh -c "nice -n 10 amass intel -org '{}' | grep -oE 'ASN: [0-9]+' | awk '{print \"AS\" \$2}' | anew '$dir/asn.txt'" || true  
    
    echo -e "${YELLOW}[+] Coletando Barramentos de IP${NC}"
    cat "$dir/asn.txt" | asnmap -silent | anew "$dir/barramentos.txt" || true
    
    echo -e "${YELLOW}[+] Reverse DNS${NC}"
    xargs -a "$dir/barramentos.txt" -I@ sh -c "nice -n 10 amass intel -cidr @ | anew '$dir/domains.txt'" || true
    
    #Second Subdomain Recon
    echo -e "${YELLOW}[+] Coletando novos Subdominios${NC}"
    cat "$dir/domains.txt" | quickcert | anew "$dir/subdomains.txt" || true
    subfinder -dL "$dir/domains.txt" -silent | anew "$dir/subdomains.txt" || true
    
    #validation subdomains
    echo -e "${YELLOW}[+] Validando subdomínios${NC}"
    cat "$dir/subdomains.txt" | httpx -silent -mc 200,202,201,203,204 | anew "$dir/subdomains_alive.txt" || true

    echo -e "${YELLOW}[+] Validando subdomínios 403${NC}"
    cat "$dir/subdomains.txt" | httpx -silent -mc 403,401 | anew "$dir/403.txt"|| true
    
    #Tech detect
     echo -e "${YELLOW}[+] Coletando Tecnologias${NC}"
     cat "$dir/subdomains_alive.txt" | httpx -silent --tech-detect | anew "$dir/techs.txt"|| true
     
    #IPs recon
    echo -e "${YELLOW}[+] Coletando IPs${NC}"
    cat "$dir/subdomains_alive.txt" | dnsx -silent -a -resp-only | grep -Ev "127\.0\.0\.1|0\.0\.0\.0" | anew "$dir/ips.txt"
    xargs -a "$dir/barramentos.txt" -I@ sh -c "echo @ | dnsx -silent -ptr | anew '$dir/ips.txt'" || true

    
    #validation ports
    echo -e "${YELLOW}[+] Validando portas dos subominios${NC}"
    naabu -l "$dir/subdomains_alive.txt" -silent | anew "$dir/subdomains_ports.txt"|| true
    
    echo -e "${YELLOW}[+] Validando portas dos IPs${NC}"
    naabu -l "$dir/ips.txt" -silent | httpx -silent | anew "$dir/ips_ports.txt"|| true
    
    #EnumRust
    echo -e "${YELLOW}[+] EnumRust${NC}"
    cd "$dir"
    sudo enumrust -f domains.txt
    sudo enumrust -f subdomains.txt
    cd ..
    
    #Cloud Enumeration
    echo -e "${YELLOW}[+] Cloud Enumeration${NC}"
    xargs -a "$dir/domains.txt" -I@ sh -c 'python3 ~/cloud_enum/cloud_enum.py -k @ -k "$(echo @ | cut -d"." -f1)"  2>&1 | grep -Ev "^[0-9]+/[0-9]+$" | grep -v -E "Connection error on|HTTPConnectionPool|ConnectionResetError|DNS Timeout|Elapsed time|Timeout|Brute-forcing|Breaking|NewConnectionError|brute-forcing|exceeded" | anew "'"$dir/cloud_enumeration.txt"'"'


    echo -e "${GREEN}[+] Recon completo. Resultados em ${dir}${NC}"|| true
}

# Modo Fuzzing
fuzzing_mode() {
    echo -e "${YELLOW}[+] Iniciando FUZZING ${NC}"
    
    #fuzzing
    echo -e "${YELLOW}[+] FUZZING: KATANA ${NC}"
    cat "$dir/subdomains_alive.txt" | katana -silent | anew "$dir/fuzzing.txt" || true

    echo -e "${YELLOW}[+] FUZZING: URLFINDER${NC}"
    urlfinder -list "$dir/subdomains_alive.txt" -silent | anew "$dir/fuzzing.txt" || true

    echo -e "${YELLOW}[+] FUZZING: GAU ${NC}"
    cat "$dir/subdomains_alive.txt" | gau | anew "$dir/fuzzing.txt" || true
    
    echo -e "${YELLOW}[+] FUZZING: WAYBACKURLS ${NC}"
    cat "$dir/subdomains_alive.txt" | waybackurls | grep -f "$dir/subdomains_alive.txt" | anew "$dir/fuzzing.txt" || true
    
    echo -e "${YELLOW}[+] FUZZING: VALIDATING ${NC}"
    cat "$dir/fuzzing.txt" | httpx -silent -mc 200,201,202,203,204 | anew "$dir/fuzzing_alive.txt" || true

    echo -e "${YELLOW}[+] FUZZING 403 ${NC}"
    cat "$dir/fuzzing.txt" | httpx -silent -mc 403,401 | anew "$dir/403.txt" || true
    
    #JS & TXT fuzzing
    echo -e "${YELLOW}[+] FUZZING: JS & TXT${NC}"
    cat "$dir/fuzzing.txt"  | grep -aE '\.(js|txt)$' | httpx -silent -mc 200,202,201,203,204 | anew "$dir/js_txt.txt" || true
    cat "$dir/subdomains_ports.txt" | getJS | anew "$dir/js_txt.txt" || true

    #parameters extracting
    echo -e "${YELLOW}[+] COLETANDO E EXTRAINDO PARAMETROS ${NC}"
    arjun -i "$dir/fuzzing.txt" -oT "$dir/arjun_parameters.txt"
    cat "$dir/arjun_parameters.txt" | httpx -silent -mc 403,401 | anew "$dir/403.txt"
    cat "$dir/arjun_parameters.txt" | anew "$dir/fuzzing.txt"
    python3 ~/smarthunt/paramextractor.py "$dir/fuzzing.txt" || true

    #cut paths
    echo -e "${YELLOW}[+] CUT PATHS ${NC}"
    cd "$dir"
    cat fuzzing.txt | urlextract && mv urlextractOutput.txt paths.txt|| true
    cd ..

    #concat
    echo -e "${YELLOW}[+] CONCAT ${NC}"
    python3 ~/smarthunt/concat.py "$dir/paths.txt" "$dir/parameters.txt"
    cat "$dir/fuzzingconcat.txt" | anew "$dir/fuzzing.txt"
    
    #FFUF FUZZING
    echo -e "${YELLOW}[+] FUZZING: CRIANDO LISTA PARA O FFUF ${NC}"
    awk '{if($0~/^https?:\/\/[^\/]+\/?$/){if(substr($0,length($0))=="/"){print $0"FUZZ"}else{print $0"/FUZZ"}}else if($0~/\/$/){print $0"FUZZ"}else{sub(/\/[^\/]+$/, "/FUZZ");print}}' "$dir/fuzzing.txt" | anew "$dir/fuzzing_ffuf.txt" || true
    
    awk '{if($0~/^https?:\/\/[^\/]+\/?$/){if(substr($0,length($0))=="/"){print $0"FUZZ"}else{print $0"/FUZZ"}}else if($0~/\/$/){print $0"FUZZ"}else{sub(/\/[^\/]+$/, "/FUZZ");print}}' "$dir/paths.txt" | anew "$dir/fuzzing_ffuf.txt" || true
    
    echo -e "${YELLOW}[+] FUZZING: FFUF DIRECTORIES ${NC}"
    mkdir "$dir/directories"
   cat "$dir/fuzzing_ffuf.txt" | xargs -I{} bash -c 'host=$(echo "{}" | sed -E "s#https?://##" | cut -d"/" -f1); ffuf -u "{}" -w ~/smarthunt/directory-list.txt -s -mc 200,201,202 -of json -o "'"$dir"'/directories/results_${host}.json"' || true

    echo -e "${YELLOW}[+] FUZZING: FFUF FILES ${NC}"
    mkdir "$dir/files"
   cat "$dir/fuzzing_ffuf.txt" | xargs -I{} bash -c 'host=$(echo "{}" | sed -E "s#https?://##" | cut -d"/" -f1); ffuf -u "{}" -w ~/smarthunt/files-list.txt -s -mc 200,201,202 -of json -o "'"$dir"'/files/results_${host}.json"' || true
     
    #XSS fuzzing
    echo -e "${YELLOW}[+] FUZZING: XSS ${NC}"
    cat "$dir/fuzzing.txt" | Gxss | anew "$dir/xss.txt" || true
    
    #OR fuzzing
    echo -e "${YELLOW}[+] FUZZING: OPEN REDIRECT ${NC}"
    cat "$dir/fuzzing.txt" | grep -aE 'https?://[^ ]*([?&](redirect|url|next|return|go|callback|r|target|to|out|view|link|dest|destination|forward|continue|nav|ref|goto|data|returnTo|return_url|returnUrl|redirect_uri|redirect_url|redirectUrl|redirectTo|RetURL|returl)=)' | anew "$dir/open_redirect.txt" || true

    #interesting files fuzzing 
    echo -e "${YELLOW}[+] FUZZING: INTERSTING FILES ${NC}" 
    cat "$dir/fuzzing.txt" | grep -aE '\.(git|conf|zip|env|bak|sql|pdf|db|swp|old|backup|key|csv|ppt|pptx|sxw|rtf|docx|odt|pem|cfg|ini|log)$'  | httpx -silent -mc 200,202,201,203,204 | anew "$dir/interestingfiles.txt" || true
    
    echo -e "${YELLOW}[+] Fuzzing completo. Resultados em ${dir}${NC}"
    
    
}
exploit_mode() {
    echo -e "${RED}[+] Iniciando EXPLOIT${NC}"

    mkdir -p "$dir/vulns"

    #find github leaks
    echo -e "${YELLOW}[+] FINDING GITHUB LEAKS ${NC}"
    read -p "digite o nome da empresa: " org
    trufflehog github --org=$org  2>&1 | grep -Ev "info-0|Unearth your secrets|error" | tee "$dir/vulns/githubleaks.txt" || true

    #find subdomain takeovers
    echo -e "${YELLOW}[+] FINDING SUBDOMAIN TAKEOVER ${NC}"
    subjack -w "$dir/subdomains.txt" | tee "$dir/vulns/subdomain_takeover.txt"
    
    #Scanning JS
    echo -e "${YELLOW}[+] Scanning JS ${NC}"
    xargs -a "$dir/js_txt.txt" -I@ sh -c "python3 ~/secretfinder/SecretFinder.py -i @ -e -o cli 2>&1 | anew '$dir/vulns/information_exposure.txt'" || true
    
    #find CVEs on IPs
    echo -e "${YELLOW}[+] FINDING CVEs ON IPs ${NC}"
    cat "$dir/ips.txt" | sdlookup -json | grep -Eo '"ip":"[^"]+"|"vulns":\[.*?\]' | anew "$dir/vulns/CVEs_IPs.txt" || true
    
    #Find 403 Bypass
    echo -e "${YELLOW}[+] FINDING 403 BYPASS ${NC}"
    xargs -a "$dir/403.txt" -I@ sh -c "403bypass -u @ --exploit | grep -A 2 -E 'Status: 20[0-9]' | anew '$dir/vulns/403bypass.txt'" || true
    
    #find Open Redirect
    echo -e "${YELLOW}[+] FINDING OPEN REDIRECT ${NC}"
    redirectfinder "$dir/open_redirect.txt" | anew "$dir/vulns/openredirect.txt"
    
    #find XSS
    echo -e "${YELLOW}[+] FINDING XSS ${NC}"
    xssfinder "$dir/xss.txt" | anew "$dir/vulns/xss.txt"

    #find Cors Misconfiguration
    echo -e "${YELLOW}[+] FINDING Cors Misconfiguration ${NC}"
    cat "$dir/subdomains_alive.txt" | corsfinder -output "$dir/vulns/cors.txt"
    
    #Nuclei
    echo -e "${YELLOW}[+] NUCLEI ${NC}"
    xargs -a "$dir/subdomains_ports.txt" -n 1 -P 5 -I@ sh -c "nice -n 10 nuclei --silent -s low,medium,high,critical -rl 30 -c 10 | anew '$dir/vulns/nuclei.txt'"
    xargs -a "$dir/subdomains_alive.txt" -n 1 -P 5 -I@ sh -c "nice -n 10 nuclei --silent -s low,medium,high,critical -rl 30 -c 10 | anew '$dir/vulns/nuclei.txt'"
    xargs -a "$dir/ips_ports.txt" -n 1 -P 5 -I@ sh -c "nice -n 10 nuclei --silent -s low,medium,high,critical -rl 30 -c 10 | anew '$dir/vulns/nuclei.txt'"
    xargs -a "$dir/ips_ports.txt" -n 1 -P 5 -I@ sh -c "nice -n 10 nuclei --silent -s low,medium,high,critical -rl 30 -c 10 | anew '$dir/vulns/nuclei.txt'"
    xargs -a "$dir/fuzzing_alive.txt" -n 1 -P 5 -I@ sh -c "nice -n 10 nuclei --silent -s low,medium,high,critical -rl 30 -c 10 | anew '$dir/vulns/nuclei.txt'"
 }

# Help
show_help() {
    echo "Uso: $0  <diretorio> [modo]"
    echo "O diretorio deve conter um arquivo: domains.txt com o(s) domínios a serem coletados"
    echo "Modos disponíveis:"
    echo "  --recon    : Coleta de informações (padrão)"
    echo "  --fuzzing  : Executa fuzzing "
    echo "  --exploit  : Testa vulnerabilidades"
    echo ""
    echo "Ex: $0  directory/domain --fuzzing (ou $0 . --recon se estiver dentro do diretorio que está o domains.txt)"
    echo "Hint: utilize nesta ordem: 1.recon, 2.fuzzing, 3.exploit para que a tool funcione corretamente"
    exit 0
}

# Main
[ -z "$1" ] && show_help                                                                                            

dir="$1"
#dir="${2:-.}"
mode="${2:---recon}"

mkdir -p "$dir" || { echo -e "${RED}[ERRO] Falha ao criar diretório${NC}"; exit 1; }
check_deps

case "$mode" in
    "--recon")
        recon_mode
        ;;
    "--fuzzing")
        fuzzing_mode
        ;;
    "--exploit")
        exploit_mode
        ;;
    *)
        echo -e "${RED}[ERRO] Modo inválido${NC}"
        show_help
        ;;
esac
