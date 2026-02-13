package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atotto/clipboard"
	"github.com/grafov/m3u8"
	"github.com/schollz/progressbar/v3"
)

var client *http.Client

// 全局变量统计下载字节数，用于计算速度
var globalWrittenBytes int64

const DefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"

func main() {
	fmt.Println("=== Golang M3U8 高级下载器 (v2.0) ===")

	// 1. 读取剪贴板并解析
	content, err := clipboard.ReadAll()
	if err != nil {
		fmt.Printf("错误: 无法读取剪贴板: %v\n", err)
		return
	}

	rawUrl, headers := parseInput(content)
	if rawUrl == "" {
		fmt.Println("警告: 剪贴板中未识别到有效的 URL 或支持的格式。")
		fmt.Println("请确保你复制的是 Chrome Network 面板中的 'Copy as cURL', 'Copy as PowerShell', 或 'Copy as fetch'")
		fmt.Println("按回车键退出...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		return
	}

	fmt.Printf("\n[已识别 URL]: %s\n", rawUrl)
	fmt.Printf("[已识别 Headers]: %d 个\n", len(headers))
	for k, v := range headers {
		fmt.Printf("  %s: %s\n", k, v)
	}
	fmt.Print("\n确认下载信息无误? (按回车继续，Ctrl+C 退出): ")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	// 2. 收集用户输入
	reader := bufio.NewReader(os.Stdin)

	// --- 新增：并发数询问 ---
	fmt.Print("输入并发数 (回车默认 4): ")
	concStr, _ := reader.ReadString('\n')
	concStr = strings.TrimSpace(concStr)
	concurrency := 4 // 默认值
	if concStr != "" {
		c, err := strconv.Atoi(concStr)
		if err == nil && c > 0 {
			concurrency = c
		} else {
			fmt.Println("输入格式有误，使用默认值 4")
		}
	}
	fmt.Printf("当前并发数: %d\n", concurrency)

	// 代理
	fmt.Print("输入代理地址 (例如 http://127.0.0.1:7890，无代理直接回车): ")
	proxyStr, _ := reader.ReadString('\n')
	proxyStr = strings.TrimSpace(proxyStr)

	// 设置 HTTP Client
	setupHttpClient(proxyStr)

	// 下载路径
	defaultDir, _ := os.UserHomeDir()
	defaultDir = filepath.Join(defaultDir, "Downloads")
	fmt.Printf("输入下载保存路径 (默认: %s): ", defaultDir)
	savePath, _ := reader.ReadString('\n')
	savePath = strings.TrimSpace(savePath)
	if savePath == "" {
		savePath = defaultDir
	}

	// 文件名
	fmt.Print("输入合并后的文件名 (不含后缀，留空则使用时间戳): ")
	fileName, _ := reader.ReadString('\n')
	fileName = strings.TrimSpace(fileName)

	timestamp := time.Now().Format("20060102_150405")
	if fileName == "" {
		fileName = timestamp
	}

	// 创建工作目录
	workDir := filepath.Join(savePath, timestamp)
	err = os.MkdirAll(workDir, 0755)
	if err != nil {
		fmt.Printf("无法创建目录: %v\n", err)
		return
	}
	fmt.Printf("\n工作目录: %s\n", workDir)

	// 3. 处理 M3U8
	finalM3u8Url, mediaPlaylist, err := processM3u8(rawUrl, headers)
	if err != nil {
		fmt.Printf("M3U8 处理失败: %v\n", err)
		return
	}

	// 4. 下载分片 (传入并发数)
	fmt.Println("\n开始下载分片...")
	// 重置计数器
	atomic.StoreInt64(&globalWrittenBytes, 0)
	err = downloadSegments(finalM3u8Url, mediaPlaylist, headers, workDir, concurrency)
	if err != nil {
		fmt.Printf("下载过程中出错: %v\n", err)
		return
	}

	// 5. 合并
	fmt.Print("\n是否使用 ffmpeg 合并为 MP4? (Y/n, 默认 Yes): ")
	mergeConfirm, _ := reader.ReadString('\n')
	mergeConfirm = strings.TrimSpace(strings.ToLower(mergeConfirm))

	outputFile := filepath.Join(savePath, fileName+".mp4")

	if mergeConfirm == "" || mergeConfirm == "y" || mergeConfirm == "yes" {
		err := mergeFiles(workDir, outputFile)
		if err != nil {
			fmt.Printf("合并失败: %v\n", err)
		} else {
			fmt.Printf("\n合并成功: %s\n", outputFile)

			// 6. 清理
			fmt.Print("是否删除碎片文件? (Y/n, 默认 Yes): ")
			delConfirm, _ := reader.ReadString('\n')
			delConfirm = strings.TrimSpace(strings.ToLower(delConfirm))
			if delConfirm == "" || delConfirm == "y" || delConfirm == "yes" {
				os.RemoveAll(workDir)
				fmt.Println("碎片已清理。")
			}
		}
	}

	fmt.Println("\n任务结束。")
}

// setupHttpClient 配置全局 HTTP 客户端
func setupHttpClient(proxyStr string) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}
	if proxyStr != "" {
		proxyUrl, err := url.Parse(proxyStr)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyUrl)
		} else {
			fmt.Println("代理地址格式错误，将不使用代理。")
		}
	}
	client = &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second, // 增加超时时间防止大分片超时
	}
}

// processM3u8 处理主播放列表和嵌套逻辑
func processM3u8(m3u8Url string, headers map[string]string) (string, *m3u8.MediaPlaylist, error) {
	req, _ := http.NewRequest("GET", m3u8Url, nil)
	setSafeHeaders(req, headers)
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	p, listType, err := m3u8.DecodeFrom(resp.Body, true)
	if err != nil {
		return "", nil, err
	}

	// 如果是主播放列表 (Master Playlist)，也就是嵌套列表
	if listType == m3u8.MASTER {
		masterParams := p.(*m3u8.MasterPlaylist)
		fmt.Println("\n检测到多级列表 (Master Playlist)，请选择：")
		for i, v := range masterParams.Variants {
			info := fmt.Sprintf("Bandwidth: %d, Resolution: %s", v.Bandwidth, v.Resolution)
			fmt.Printf("[%d] %s\n", i+1, info)
		}

		fmt.Print("输入序号 (默认 1): ")
		reader := bufio.NewReader(os.Stdin)
		selection, _ := reader.ReadString('\n')
		selection = strings.TrimSpace(selection)

		idx := 0
		if selection != "" {
			val, err := strconv.Atoi(selection)
			if err == nil && val > 0 && val <= len(masterParams.Variants) {
				idx = val - 1
			}
		}

		// 解析新的 URL
		selectedUrl := masterParams.Variants[idx].URI
		newUrl, err := resolveURL(m3u8Url, selectedUrl)
		if err != nil {
			return "", nil, err
		}
		fmt.Printf("已选择: %s\n", newUrl)
		// 递归调用以解析 Media Playlist
		return processM3u8(newUrl, headers)
	}

	if listType == m3u8.MEDIA {
		return m3u8Url, p.(*m3u8.MediaPlaylist), nil
	}

	return "", nil, fmt.Errorf("未知的 M3U8 类型")
}

// PassThru 用于统计下载流量
type PassThru struct {
	io.Reader
}

func (pt *PassThru) Read(p []byte) (int, error) {
	n, err := pt.Reader.Read(p)
	if n > 0 {
		atomic.AddInt64(&globalWrittenBytes, int64(n))
	}
	return n, err
}

// downloadSegments 下载所有分片
func downloadSegments(baseUrl string, pl *m3u8.MediaPlaylist, headers map[string]string, workDir string, concurrency int) error {
	var wg sync.WaitGroup
	// 使用用户输入的并发数
	sem := make(chan struct{}, concurrency)

	// 进度条配置优化：移除冗余的 it/s 和 复杂的 ANSI 预估
	bar := progressbar.NewOptions(int(pl.Count()),
		progressbar.OptionSetDescription("等待下载..."),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(20),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerPadding: " ",
			BarStart:      "|",
			BarEnd:        "|",
		}),
		progressbar.OptionThrottle(100*time.Millisecond), // 降低刷新频率
		progressbar.OptionClearOnFinish(),
	)

	// 启动速度监控协程
	doneCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var lastBytes int64 = 0
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				currentBytes := atomic.LoadInt64(&globalWrittenBytes)
				diff := currentBytes - lastBytes
				lastBytes = currentBytes
				// 使用固定长度的速度显示
				speedStr := formatSpeedFixed(diff)
				bar.Describe(fmt.Sprintf("下载中 [%s]", speedStr))
			}
		}
	}()

	// 缓存解密 Key，避免重复下载
	keyCache := make(map[string][]byte)
	var keyMutex sync.Mutex

	// 准备文件列表用于合并
	fileListPath := filepath.Join(workDir, "files.txt")
	fileListFile, err := os.Create(fileListPath)
	if err != nil {
		close(doneCh)
		return err
	}
	defer fileListFile.Close()

	for i, segment := range pl.Segments {
		if segment == nil {
			continue
		}

		// 写入文件列表 (ffmpeg concat format)
		tsFilename := fmt.Sprintf("%05d.ts", i)
		fileListFile.WriteString(fmt.Sprintf("file '%s'\n", tsFilename))

		wg.Add(1)
		go func(seg *m3u8.MediaSegment, idx int, filename string) {
			defer wg.Done()
			sem <- struct{}{} // 获取信号量
			defer func() { <-sem }()

			// 1. 解析分片 URL
			segUrl, _ := resolveURL(baseUrl, seg.URI)

			// 2. 处理加密 Key
			var keyBytes []byte
			var iv []byte
			if seg.Key != nil && seg.Key.URI != "" && seg.Key.Method != "" && seg.Key.Method != "NONE" {
				keyUrl, _ := resolveURL(baseUrl, seg.Key.URI)

				keyMutex.Lock()
				if k, ok := keyCache[keyUrl]; ok {
					keyBytes = k
				} else {
					// 下载 Key
					kreq, _ := http.NewRequest("GET", keyUrl, nil)
					setSafeHeaders(kreq, headers)
					kresp, err := client.Do(kreq)
					if err == nil {
						kb, _ := io.ReadAll(kresp.Body)
						kresp.Body.Close()
						keyCache[keyUrl] = kb
						keyBytes = kb
					}
				}
				keyMutex.Unlock()

				if seg.Key.IV != "" {
					// 这里的处理逻辑保持不变
				} else {
					iv = make([]byte, 16)
					binary.BigEndian.PutUint64(iv[8:], uint64(pl.SeqNo+uint64(idx)))
				}
			}

			// 3. 下载 TS 数据 (带重试)
			for retry := 0; retry < 3; retry++ {
				tsReq, _ := http.NewRequest("GET", segUrl, nil)
				setSafeHeaders(tsReq, headers)
				tsResp, err := client.Do(tsReq)
				if err != nil {
					time.Sleep(time.Second)
					continue
				}

				// 使用 PassThru 包装 Body 以统计流量
				reader := &PassThru{Reader: tsResp.Body}
				tsData, err := io.ReadAll(reader)
				tsResp.Body.Close()

				if err != nil {
					time.Sleep(time.Second)
					continue
				}

				// 4. 解密
				if len(keyBytes) > 0 {
					tsData, err = decryptAES128(tsData, keyBytes, iv, seg.Key.IV)
					if err != nil {
						// 解密失败也继续，防止崩溃
					}
				}

				// 5. 保存
				err = os.WriteFile(filepath.Join(workDir, filename), tsData, 0644)
				if err == nil {
					break // 成功
				}
			}
			bar.Add(1)
		}(segment, i, tsFilename)
	}

	wg.Wait()
	close(doneCh)
	fmt.Print("\r") // 强制回车，清理最后一行
	return nil
}

// formatSpeed 格式化速度字符串
func formatSpeed(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B/s", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.2f KB/s", float64(bytes)/1024.0)
	} else {
		return fmt.Sprintf("%.2f MB/s", float64(bytes)/1024.0/1024.0)
	}
}

// decryptAES128 处理 AES-128-CBC 解密
func decryptAES128(data, key []byte, defaultIV []byte, keyIVStr string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var iv []byte
	if keyIVStr != "" {
		keyIVStr = strings.TrimPrefix(keyIVStr, "0x")
		if len(keyIVStr) < 32 {
			pad := strings.Repeat("0", 32-len(keyIVStr))
			keyIVStr = pad + keyIVStr
		}
		iv = make([]byte, 16)
		for i := 0; i < 16; i++ {
			val, _ := strconv.ParseUint(keyIVStr[i*2:i*2+2], 16, 8)
			iv[i] = byte(val)
		}
	} else {
		iv = defaultIV
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	padding := int(data[len(data)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-padding], nil
}

// mergeFiles 调用 ffmpeg 合并
func mergeFiles(workDir, outputFile string) error {
	listPath := filepath.Join(workDir, "files.txt")
	absOutput, _ := filepath.Abs(outputFile)
	cmd := exec.Command("ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", listPath, "-c", "copy", absOutput)
	return cmd.Run()
}

// resolveURL 处理相对路径
func resolveURL(base, ref string) (string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	if u.IsAbs() {
		return ref, nil
	}
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(u).String(), nil
}

// parseInput 解析输入
func parseInput(input string) (string, map[string]string) {
	clean := strings.ReplaceAll(input, "^\"", "\"")
	clean = strings.ReplaceAll(clean, "^\r\n", " ")
	clean = strings.ReplaceAll(clean, "^\n", " ")
	clean = strings.ReplaceAll(clean, "\\\r\n", " ")
	clean = strings.ReplaceAll(clean, "\\\n", " ")
	clean = strings.ReplaceAll(clean, "`\r\n", " ")
	clean = strings.ReplaceAll(clean, "`\n", " ")
	clean = strings.ReplaceAll(clean, "\r\n", " ")
	clean = strings.ReplaceAll(clean, "\n", " ")

	urlStr := ""
	headers := make(map[string]string)

	if strings.Contains(strings.ToLower(clean), "curl") {
		reUrl := regexp.MustCompile(`curl\s+['"](http.*?)['"]`)
		matches := reUrl.FindStringSubmatch(clean)
		if len(matches) > 1 {
			urlStr = matches[1]
		}
		reHeader := regexp.MustCompile(`-H\s+['"](.*?):\s*(.*?)['"]`)
		hMatches := reHeader.FindAllStringSubmatch(clean, -1)
		for _, m := range hMatches {
			headers[m[1]] = m[2]
		}
		reHeader2 := regexp.MustCompile(`--header\s+['"](.*?):\s*(.*?)['"]`)
		hMatches2 := reHeader2.FindAllStringSubmatch(clean, -1)
		for _, m := range hMatches2 {
			headers[m[1]] = m[2]
		}
	}

	if strings.Contains(strings.ToLower(clean), "invoke-webrequest") {
		reUrl := regexp.MustCompile(`-Uri\s+"(http.*?)"`)
		matches := reUrl.FindStringSubmatch(clean)
		if len(matches) > 1 {
			urlStr = matches[1]
		}
		reHeader := regexp.MustCompile(`"([a-zA-Z0-9-]+)"\s*=\s*"(.*?)"`)
		hMatches := reHeader.FindAllStringSubmatch(clean, -1)
		for _, m := range hMatches {
			k := strings.ToLower(m[1])
			if k != "method" && k != "authority" && k != "scheme" && k != "path" {
				headers[m[1]] = m[2]
			}
		}
		if strings.Contains(clean, "$session.UserAgent") {
			reUA := regexp.MustCompile(`UserAgent\s*=\s*"(.*?)"`)
			uaM := reUA.FindStringSubmatch(clean)
			if len(uaM) > 1 {
				headers["User-Agent"] = uaM[1]
			}
		}
	}

	if strings.Contains(strings.ToLower(clean), "fetch(") {
		reUrl := regexp.MustCompile(`fetch\(\s*['"](http.*?)['"]`)
		matches := reUrl.FindStringSubmatch(clean)
		if len(matches) > 1 {
			urlStr = matches[1]
		}
		idx := strings.Index(clean, "\"headers\"")
		if idx != -1 {
			sub := clean[idx:]
			endIdx := strings.Index(sub, "}")
			if endIdx != -1 {
				headerBlock := sub[:endIdx]
				reJsonKV := regexp.MustCompile(`"([a-zA-Z0-9-]+)"\s*:\s*"(.*?)"`)
				hMatches := reJsonKV.FindAllStringSubmatch(headerBlock, -1)
				for _, m := range hMatches {
					headers[m[1]] = strings.ReplaceAll(m[2], `\"`, `"`)
				}
			}
		}
	}

	urlStr = strings.TrimSpace(urlStr)
	if urlStr == "" {
		reRawUrl := regexp.MustCompile(`https?://[^\s^"'{}\\]+`)
		matches := reRawUrl.FindString(clean)
		if matches != "" {
			urlStr = matches
		}
	}

	return urlStr, headers
}
func setSafeHeaders(req *http.Request, customHeaders map[string]string) {
	req.Header.Set("User-Agent", DefaultUA)
	for k, v := range customHeaders {
		lk := strings.ToLower(k)
		if lk != "host" && lk != "authority" && lk != "content-length" {
			req.Header.Set(k, v)
		}
	}
}

// 格式化速度字符串，并填充固定空格防止拖影
func formatSpeedFixed(bytes int64) string {
	var s string
	if bytes < 1024 {
		s = fmt.Sprintf("%d B/s", bytes)
	} else if bytes < 1024*1024 {
		s = fmt.Sprintf("%.2f KB/s", float64(bytes)/1024.0)
	} else {
		s = fmt.Sprintf("%.2f MB/s", float64(bytes)/1024.0/1024.0)
	}
	// 填充到 15 位长度，确保覆盖旧字符
	return fmt.Sprintf("%-15s", s)
}
