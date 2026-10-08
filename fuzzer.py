import requests
import concurrent.futures
import argparse
import random
import time
import sys


VALID_STATUS = [200, 202, 204, 301, 302]
TIMEOUT = 2

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)",
    "Mozilla/5.0 (Android 10; Mobile; rv:81.0)",
]

def stealth_delay():
    time.sleep(random.uniform(0.2, 0.5))

def fuzz_url(base_url, endpoint, method):
    base_url = base_url.rstrip('/')
    endpoint = endpoint.lstrip('/')
    url = f"{base_url}/{endpoint}"

    stealth_delay()
    headers = {
        "User-Agent": random.choice(USER_AGENTS)
    }

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
        elif method == "POST":
            response = requests.post(url, headers=headers, timeout=TIMEOUT, data={})
        else:
            return None

        if response.status_code in VALID_STATUS:
            print(f"[+] {url} -> {response.status_code}", file=sys.stderr)
            sys.stdout.write(f"{url}\n")
            return url

    except requests.RequestException:
        pass
    return None

def main(urls_file, wordlist_file, method, threads):
    with open(urls_file, 'r') as f:
        base_urls = [line.strip() for line in f if line.strip()]
    
    with open(wordlist_file, 'r') as f:
        endpoints = [line.strip() for line in f if line.strip()]

    print("[~] Fuzzing {} endpoints em {} URLs base com método {}...\n".format(len(endpoints), len(base_urls), method), file=sys.stderr)

    valid_urls = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for base in base_urls:
            for endpoint in endpoints:
                futures.append(executor.submit(fuzz_url, base, endpoint, method))

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                valid_urls.append(result)

    print(f"\n[✓] Total de endpoints válidos encontrados: {len(valid_urls)}", file=sys.stderr)
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Endpoint Fuzzer - Stealth Mode")
    parser.add_argument("-u", "--urls", required=True, help="Arquivo com as URLs base")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist com os endpoints")
    parser.add_argument("-m", "--method", choices=["GET", "POST"], default="GET", help="Método HTTP (default: GET)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Número de threads (default: 5)")
    args = parser.parse_args()

    main(args.urls, args.wordlist, args.method.upper(), args.threads)

