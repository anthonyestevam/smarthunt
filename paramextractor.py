import sys
import re
import os
from urllib.parse import urlparse, parse_qs

def extrair_parametros(url):
    parsed_url = urlparse(url)
    parametros = parse_qs(parsed_url.query)
    return [param for param in parametros.keys() if re.match(r"^[a-zA-Z0-9_\-]+$", param)]

if len(sys.argv) != 2:
    print(f"Uso: python {sys.argv[0]} <arquivo_com_urls>")
    sys.exit(1)

arquivo_urls = sys.argv[1]
diretorio_saida = os.path.dirname(os.path.abspath(arquivo_urls))
arquivo_saida = os.path.join(diretorio_saida, "parameters.txt")

# Carrega os parâmetros já existentes no arquivo, se houver
parametros_existentes = set()
if os.path.exists(arquivo_saida):
    with open(arquivo_saida, "r") as f:
        parametros_existentes = set(line.strip() for line in f if line.strip())

# Abrir o arquivo para escrita contínua
with open(arquivo_saida, "a") as f_out:
    with open(arquivo_urls, "r") as f_in:
        for linha in f_in:
            linha = linha.strip()
            if linha:
                parametros = extrair_parametros(linha)
                novos_parametros = set(parametros) - parametros_existentes
                
                for parametro in novos_parametros:
                    f_out.write(parametro + "\n")
                    f_out.flush()
                
                parametros_existentes.update(novos_parametros)

print(f"✅ Arquivo 'parameters.txt' gerado com sucesso em: {arquivo_saida}")
