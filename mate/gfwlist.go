package mate

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

const gfwlistDownloadURL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
const defaultInterval = time.Hour

type t int

const (
	unknown t = iota
	ip
	domain
	domainKeyword
)

func uniqueList(list []string) []string {
	m := make(map[string]bool, len(list))
	var newList []string
	for _, v := range list {
		if m[v] || v == "" {
			continue
		}
		newList = append(newList, v)
		m[v] = true
	}
	return newList
}

type gfwlistProvider struct {
	interval time.Duration

	mu    sync.RWMutex
	rules []byte
}

func (s *gfwlistProvider) Handle(wr http.ResponseWriter) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	wr.Write(s.rules)
}

func (s *gfwlistProvider) renderClashRules(domainList, ipList, domainKeywordList []string) []string {
	rules := make([]string, 0, len(domainList)+len(ipList)+len(domainKeywordList))

	for _, domainKeyword := range domainKeywordList {
		rules = append(rules, fmt.Sprintf("DOMAIN-KEYWORD,%s", domainKeyword))
	}
	for _, ip := range ipList {
		rules = append(rules, fmt.Sprintf("SRC-IP-CIDR,%s/32", ip))
	}
	for _, domain := range domainList {
		rules = append(rules, fmt.Sprintf("DOMAIN-SUFFIX,%s", domain))
	}

	return rules
}

func (s *gfwlistProvider) update() error {
	rc, err := s.download()
	if err != nil {
		return err
	}
	domain, ip, domainKeyword, err := s.parseToList(rc)
	if err != nil {
		return err
	}

	rules := s.renderClashRules(domain, ip, domainKeyword)
	b, err := yaml.Marshal(map[string]interface{}{
		"payload": rules,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.rules = b
	s.mu.Unlock()
	return nil
}

func (s *gfwlistProvider) start() {
	update := func() {
		start := time.Now()
		err := s.update()
		if err != nil {
			log.Println("update gfwlist failed, ", err)
		} else {
			log.Println("update success, ", time.Now().Sub(start))
		}
	}
	update()
	interval := s.interval
	if interval <= 0 {
		interval = defaultInterval
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for range timer.C {
		update()
		timer.Reset(interval)
	}
}

func (s *gfwlistProvider) download() (io.ReadCloser, error) {
	// TODO: support download with proxy
	resp, err := http.Get(gfwlistDownloadURL)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("download gfwlist failed, code: %d, body: %s", resp.StatusCode, body)
	}
	return resp.Body, nil
}

func tryGetDomainOrIP(v string) (t, string) {
	return tryGetDomain(v, false)
}

func tryGetDomain(v string, full bool) (_ t, vv string) {
	defer func() {
		vv = strings.Trim(vv, "*")
	}()
	if !strings.HasPrefix(v, "http://") {
		v = "http://" + v
	}
	v, _ = url.QueryUnescape(v)
	parse, err := url.Parse(v)
	if err != nil {
		log.Printf("parse %s as url failed, %s", v, err)
		return 0, ""
	}
	if isIP(parse.Hostname()) {
		return ip, parse.Hostname()
	}
	if full {
		return domain, parse.Hostname()
	}
	pairs := strings.Split(parse.Hostname(), ".")
	return domain, strings.Join(pairs[len(pairs)-2:], ".")
}

func isIP(v string) bool {
	return net.ParseIP(v) != nil
}

func (s *gfwlistProvider) parseLine(line string) (t, string) {
	if strings.HasPrefix(line, "|") {
		line = strings.TrimLeft(line, "|")
		line = strings.TrimLeft(line, "http://")
		return tryGetDomain(line, true)
	} else if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "http://") {
		line = strings.TrimLeft(line, "|")
		line = strings.TrimLeft(line, "http://")
		line = strings.TrimLeft(line, "https://")
		return tryGetDomainOrIP(line)
	} else if strings.HasPrefix(line, ".") {
		line = strings.TrimLeft(line, ".")
		typ, v := tryGetDomainOrIP(line)
		if strings.HasSuffix(v, "*") {
			return domainKeyword, strings.Split(v, ".")[0]
		} else {
			return typ, v
		}
	} else if strings.Contains(line, ".") {
		// try as url
		return tryGetDomain(line, true)
	} else if isIP(line) {
		return ip, line
	} else {
		// skip
	}
	return unknown, ""
}

/**
parseToList parse the raw gfwlist to domain and ip list.
*/
func (s *gfwlistProvider) parseToList(rc io.ReadCloser) (domainList []string, ipList []string, domainKeywordList []string, _ error) {
	defer rc.Close()
	scanner := bufio.NewScanner(base64.NewDecoder(base64.StdEncoding, rc))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		switch line[0] {
		case '!', '[', '/', '@':
			// skip comment, regex, allowList,
			continue
		}

		typ, v := s.parseLine(line)
		switch typ {
		case ip:
			ipList = append(ipList, v)
		case domain:
			domainList = append(domainList, v)
		case domainKeyword:
			domainKeywordList = append(domainKeywordList, v)
		}
	}
	return uniqueList(domainList), uniqueList(ipList), domainKeywordList, scanner.Err()
}

func newGfwlistProvider() *gfwlistProvider {
	s := &gfwlistProvider{}
	go s.start()
	return s
}
