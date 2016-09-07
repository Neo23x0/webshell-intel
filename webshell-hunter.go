// Webshell Hunter
// Florian Roth
//
// Based on Web Crawler code by Suhail Abood
// http://www.vervesearch.com/blog/how-to-make-a-simple-web-crawler-in-go/

package main

//import packages
import (
	"fmt"		//GO’s base package
	"io/ioutil"	//reading/writing data from input/output streams
	"net/http"	//for sending HTTP requests
	"net/url"	//for URL formatting
	"regexp"	//regular expressions
	"runtime"	//GO runtime (used to set the number of threads to be used)
	"strings"	//string manipulation and testing
	"flag"
	"path/filepath"
	"os"
	"bufio"
)

//how many threads to use within the application
const NCPU = 1

//IOCs
//filename signatures
var filenames []string

//URL filter function definition
type filterFunc func(string, Crawler) bool

//Check function definition
type checkFunc func(string, Crawler) bool

//Our crawler structure definition
type Crawler struct {
	//the base URL of the website being crawled
	host string
	//a channel on which the crawler will receive new (unfiltered) URLs to crawl
	//the crawler will pass everything received from this channel
	//through the chain of filters we have
	//and only allowed URLs will be passed to the filteredUrls channel
	urls chan string
	//a channel on which the crawler will receive filtered URLs.
	filteredUrls chan string //a channel
	//a channel on which the crawler will receive URLs to check for web shells.
	checkUrls chan string //a channel
	//a slice that contains the filters we want to apply on the URLs.
	filters []filterFunc
	//a slice that contains the checks that we want to apply on the URLs.
	checks []checkFunc
	//a regular expression pointer to the RegExp that will be used to extract the
	//URLs from each request.
	re *regexp.Regexp
	//an integer to track how many URLs have been crawled
	count int
}

//starts the crawler
//the method starts two GO functions
//the first one waits for new URLs as they
//get extracted.
//the second waits for filtered URLs as they
//pass through all the registered filters
func (crawler *Crawler) start() {
	//wait for new URLs to be extracted and passed to the URLs channel.
	go func() {
		for n := range crawler.urls {
			//filter the url
			go crawler.filter(n)
			// check the url
			go crawler.check(n)
		}
	}()

	//wait for filtered URLs to arrive through the filteredUrls channel
	go func() {
		for s := range crawler.filteredUrls {
			//print the newly received filtered URL
			fmt.Println(s)
			//increment the crawl count
			crawler.count++
			//start a new GO routine to crawl the filtered URL
			go crawler.crawl(s)
		}
	}()

	//wait for evil URLs to arrive through the checkUrls channel
	go func() {
		for s := range crawler.checkUrls {
			//print the newly received filtered URL
			// fmt.Println("Check: ", s)
			//start a new GO routine to crawl the filtered URL
			go crawler.checkUrl(s)
		}
	}()
}

//given a URL, the method will send an HTTP GET request
//extract the response body
//extract the URLs from the body
func (crawler *Crawler) crawl(url string) {
	//send http request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("An error has occured")
		fmt.Println(err)
	} else {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Read error has occured")
		} else {
			strBody := string(body)
			crawler.extractUrls(url, strBody)
		}

	}
}

//check a given URL for a valid response
func (crawler *Crawler) checkUrl(url string) {
	//send http request
	httpClient := &http.Client{}

	fmt.Println("Checking: ", url)

	req, reqErr := http.NewRequest("GET", url, nil)
	if reqErr != nil {
		fmt.Println(reqErr)
		return
	}
	req.Header.Set("Connection", "close")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	} else {
		fmt.Println(resp.StatusCode)
		if resp.StatusCode > 200 {
			return
		}
		// fmt.Printf("%s", resp.Body)
		fmt.Println("MATCH FOUND!!! URL: ", url)
	}
	defer resp.Body.Close()
	return
}

//adds a new URL filter to the crawler
func (crawler *Crawler) addFilter(filter filterFunc) *Crawler {
	crawler.filters = append(crawler.filters, filter)
	return crawler
}

//adds a new Check to the crawler
func (crawler *Crawler) addCheck(check checkFunc) *Crawler {
	crawler.checks = append(crawler.checks, check)
	return crawler
}

//stops the crawler by closing both the URLs channel
//and the filtered URLs channel
func (crawler *Crawler) stop() {
	close(crawler.urls)
	close(crawler.filteredUrls)
}

//given a URL, the method will apply all the filters
//on that URL, if and only if, it passes through all
//the filters, it will then be passed to the filteredUrls channel
func (crawler *Crawler) filter(url string) {
	temp := false
	for _, fn := range crawler.filters {
		temp = fn(url, *crawler)
		if temp != true {
			return
		}
	}
	crawler.filteredUrls <- url
}

//given a URL, the method will apply all the checks on that URL
func (crawler *Crawler) check(url string) {
	for _, ck := range crawler.checks {
		ck(url, *crawler)
	}
}

//given the crawled URL, and its body, the method
//will extract the URLs from the body
//and generate absolute URLs to be crawled by the
//crawler
//the extracted URLs will be passed to the URLs channel
func (crawler *Crawler) extractUrls(Url, body string) {
	newUrls := crawler.re.FindAllStringSubmatch(body, -1)
	u := ""
	baseUrl, _ := url.Parse(Url)
	if newUrls != nil {
		for _, z := range newUrls {
			u = z[1]
			ur, err := url.Parse(z[1])
			if err == nil {
				if ur.IsAbs() == true {
					crawler.urls <- u
				} else if ur.IsAbs() == false {
					crawler.urls <- baseUrl.ResolveReference(ur).String()
				} else if strings.HasPrefix(u, "//") {
					crawler.urls <- "http:" + u
				} else if strings.HasPrefix(u, "/") {
					crawler.urls <- crawler.host + u
				} else {
					crawler.urls <- Url + u
				}
			}
		}
	}
}

func (crawler *Crawler) readSigs(filenameSigDir string) {
	fmt.Println("Reading signatures from ", filenameSigDir)
	// Check files in signature directories
	files, _ := ioutil.ReadDir(filenameSigDir)
	re := regexp.MustCompile(`[\r\n\t]`)
	// Looping through signature files
	for _, f := range files {
		extension := filepath.Ext(f.Name())
		filePath := filepath.Join(filenameSigDir, f.Name())
		if extension != ".txt" {
			continue
		}
		// Read signatures
		fileReader, err := os.Open(filePath)
		if err != nil {
			fmt.Println("Error opening signature file: ", filePath)
		}
		// Process file line by line
		scanner := bufio.NewScanner(fileReader)
		for scanner.Scan() {
			line := scanner.Text()
			// Check if line is not empty or commented
			match_empty, _ := regexp.MatchString(`(^[\s\t]*$|^[\s]*#)`, line)
			if match_empty {
				continue
			}
			line = re.ReplaceAllString(line, "")
			filenames = append(filenames, line)
		}
	}
}

func main() {
	// Parameters
	var urltarget string
	var sigpath string
	// Get parameters
	flag.StringVar(&urltarget, "u", "http://www.thesaurus.com/", "Target URL")
	flag.StringVar(&sigpath, "s", "./sigs/filenames", "Filename signatures path")

	// Parse
	flag.Parse()

	// Get target hostname
	u, _ := url.Parse(urltarget)

	//set how many processes (threads to use)
	runtime.GOMAXPROCS(NCPU)

	//create a new instance of the crawler structure
	c := Crawler{
		urltarget,
		make(chan string),
		make(chan string),
		make(chan string),
		make([]filterFunc, 0),
		make([]checkFunc, 0),
		regexp.MustCompile("(?s)<a[ t]+.*?href=\"(http.*?)\".*?>.*?</a>"),
		0,
	}

	//read the signatures
	c.readSigs(sigpath)

	//add our only filter which makes sure that we are only
	//crawling internal URLs.
	c.addFilter(func(Url string, crawler Crawler) bool {
		return strings.Contains(Url, u.Host)
	}).start()

	//add our first check function
	c.addCheck(func(Url string, crawler Crawler) bool {
		for _, f := range filenames {
			checkUrl := fmt.Sprintf("%s%s", Url, f)
			crawler.checkUrls <- checkUrl
		}
		return true
	}).start()

	c.urls <- c.host

	var input string
	fmt.Scanln(&input)
}