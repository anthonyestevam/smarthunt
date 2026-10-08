package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
	tld "github.com/jpillora/go-tld"
	"github.com/fatih/color"
	"flag"
	"strings"
	"regexp"
)

var f *os.File
var Threads int
var header string
var method string
var wildcard bool 
var req *http.Request
var output string
var result *os.File


func getClient() *http.Client {          
	tr := &http.Transport{
		MaxIdleConns:    30,
		IdleConnTimeout: time.Second,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * 10,
			KeepAlive: time.Second,
		}).DialContext,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       time.Second * 10,
	}
}

func custom_header(c *http.Client, header string, req *http.Request) {
	parse := strings.ReplaceAll(header, "\\n", "\n")
	var h_name string
	var v_name string
	r := regexp.MustCompile(`(.*):\s(.*)`)
	matches := r.FindStringSubmatch(parse)
	for i, match := range matches {
		if i == 1 {
			h_name = match
		}
		if i == 2 {
			v_name = match
		}

	}
	req.Header.Set(h_name, v_name)
}

func add_method(req *http.Request, method string, u string) *http.Request {
	if method != "GET" {
		req, _ = http.NewRequest(method, u, nil)
	} else {

		req, _ = http.NewRequest(method, u, nil)
			
	}

	return req	
}

func requester(c *http.Client,  method string, u string, origins []string, header string) {
	for _, p := range origins {

		req = add_method(req, method, u)

		req.Header.Set("Origin", p)
		if header != " " {
			custom_header(c, header, req)
		}
		resp, err := c.Do(req)
		if resp != nil {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
		if err != nil {
			w := bufio.NewWriter(f)  
			w.WriteString(u + "\n")
			w.Flush()
			return
		}
		
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == p && acac == "true" {
			color.HiRed("\n[-] Misconfiguration found!")
			color.HiCyan("URL: %s", u)
			color.HiGreen("Access-Control-Allow-Origin: %s", p)
			color.HiGreen("Access-Control-Allow-Credentials: %s", acac)
			res := bufio.NewWriter(result)
			res.WriteString("\n[-] Misconfiguration found!")
			res.WriteString("\nURL: " + u)
			res.WriteString("\nAccess-Control-Allow-Origin: " + p)
			res.WriteString("\nAccess-Control-Allow-Credentials: " + acac + "\n\n")
			res.Flush()
}
						
		
		}
	}


func parser(u string) ([]string,  error) {
	var parsed[] string 
	url, err := tld.Parse(u)
	if err != nil {
		return []string{}, err
	} 
	subdomain := url.Subdomain
	domain := url.Domain
	tld := url.TLD
	return append(parsed, subdomain, domain, tld), nil 
}

func anyorigin(wildcard bool) []string {
	origins := []string{
		"http://thxny.com",
		"https://thxny.com",
	}
	if wildcard == true {
		origins = append(origins, "*")
	}
	return origins
	
}
	

func prefix(things []string) []string {
	origins := []string{"https://" + things[1] + ".thxny.com", "https://" + things[1] + "." +  things[2] + ".thxny.com"}	
	return origins
}

func suffix(things []string) []string {
	origins := []string{"https://" + "thxny" + things[1] + "." + things[2], "https://" + "thxny.com" + "." + things[1] + "." + things[2]}	
	return origins
}

func notescapedot(things []string) []string  {
	origins := []string{"https://" + things[0] + "S" + things[1] + things[2]}	
	return origins
}


func null() []string  {
	origins := []string{"null"}	
	return origins
}

func thirdparties() []string {           
	origins := []string{
		"http://jsbin.com",
		"https://codepen.io",
		"https://jsfiddle.net",
		"http://www.webdevout.net",
		"https://repl.it",
	}
	return origins
}

func spicalchars(things []string) []string {
	origins := []string{}
	chars := []string{"_","-","{","}","^","%60","!","~","`",";","|","&","(",")","*","'","\"","$","=","+","%0b"}
	permute := []string{"https://" + things[0] + "." + things[1] + "." + things[2] + "%s" + ".thxny.com"}
	for i, per := range permute {
		for _, char := range chars{
			permute[i] = fmt.Sprintf(per, char)
			origins = append(origins, permute[i])
		}
	} 
	return origins
}

func totalwaystotest(c *http.Client, method string, u string, wildcard bool, header string)  { 	
	things, _ := parser(u)
	
	AnyOrigin := anyorigin(wildcard)
	requester(c, method, u, AnyOrigin, header)
	
	Prefix := prefix(things)
	requester(c, method, u, Prefix, header)
	
	Suffix := suffix(things)
	requester(c, method, u, Suffix, header)
	
	Escaped := notescapedot(things)
	requester(c, method, u, Escaped, header)
	
	Null := null()
	requester(c, method, u, Null, header)

	Third := thirdparties()
	requester(c, method, u, Third, header)

	Specialchars := spicalchars(things)
	requester(c, method, u, Specialchars, header)

}


func ParseArguments() {
	flag.IntVar(&Threads, "t", 40, "Number of workers to use..default 40. Ex: -t 50")
	flag.BoolVar(&wildcard, "wildcard", false, "If enabled..then * is checked in Access-Control-Allow-Origin. Ex: -wildcard true")	
	flag.StringVar(&header, "header",  " ", "Add any custom header if required. Ex: -header \"Cookie: Session=12cbcx....\"")
	flag.StringVar(&method, "method",  "GET", "Add method name if required. Ex: -method PUT. Default \"GET\"")
	flag.StringVar(&output, "output", " ", "Output to save as")
	flag.Parse()
}


func main() {
	ParseArguments()
	checkin, _ := os.Stdin.Stat()

	if checkin.Mode()&os.ModeNamedPipe > 0 {
		// Removido: Banner()

		if output != " " {
			result, _ = os.Create(output)
		}

		// Removido: print de método
		// Removido: status prints e spinner

		urls := make(chan string, Threads)
		processGroup := new(sync.WaitGroup)
		processGroup.Add(Threads)

		for i := 0; i < Threads; i++ {
			c := getClient()
			go func() {
				defer processGroup.Done()
				for u := range urls {
					totalwaystotest(c, method, u, wildcard, header)
				}
			}()
		}

		sc := bufio.NewScanner(os.Stdin)

		for sc.Scan() {
			urls <- sc.Text()
		}

		close(urls)
		processGroup.Wait()
	} else {
		color.HiRed("\n[!] Check: Corsme -h for arguments")
	}
}
