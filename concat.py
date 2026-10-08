import requests
import sys
import os

if len(sys.argv) != 3:
    print(f"Uso: python {sys.argv[0]} <arquivo_urls> <arquivo_parametros>")
    sys.exit(1)

arquivo_urls = sys.argv[1]
arquivo_parametros = sys.argv[2]

STATUS_VALIDOS = {200, 201, 202, 204, 203, 301, 302}
HTTP_METHODS = ["GET", "POST"]

# Diretório onde o arquivo de URLs está localizado
diretorio_saida = os.path.dirname(os.path.abspath(arquivo_urls))
caminho_arquivo_saida = os.path.join(diretorio_saida, "fuzzingconcat.txt")

# Ler URLs e parâmetros
with open(arquivo_urls, "r") as f:
    urls = [line.strip() for line in f if line.strip()]

with open(arquivo_parametros, "r") as f:
    parametros = [line.strip() for line in f if line.strip()]


with open(caminho_arquivo_saida, "a") as f_out:
    for url in urls:
        for parametro in parametros:
            formatted_url = url if url.endswith("/") else url + "/"
            full_url = f"{formatted_url}?{parametro}="

            for method in HTTP_METHODS:
                try:
                    response = requests.request(method, full_url, timeout=5, allow_redirects=True)
                    if response.status_code in STATUS_VALIDOS:
                        print(f"[VALID] {method} {full_url} -> {response.status_code}")
                        f_out.write(full_url + "\n")
                        f_out.flush()
                        break
                except requests.RequestException:
                    pass

print(f"\n✅ URLs válidas foram gravadas em: {caminho_arquivo_saida}")
