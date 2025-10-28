package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// --- CẤU HÌNH VÀ HẰNG SỐ ---
const (
	MaxRetries                = 3 // Số lần thử lại cho mỗi API riêng lẻ
	InitialDelayMs            = 1
	MaxConsecutiveSuccess     = 200
	MinConsecutiveFail        = 5
)

type DeviceInfo struct {
	Model    string
	Version  string
	ApiLevel int
}

var devices = []DeviceInfo{
	{"Pixel 7 Pro", "13", 33},
	{"Pixel 6", "12", 31},
	{"Pixel 5", "11", 30},
	{"Samsung Galaxy S23", "13", 33},
	{"Samsung Galaxy S21", "12", 31},
	{"Oppo Reno 10", "13", 33},
	{"Oppo Reno 8", "12", 31},
	{"Xiaomi 13 Pro", "13", 33},
	{"Xiaomi Mi 11", "12", 31},
}

func randomDevice() DeviceInfo {
	return devices[rand.Intn(len(devices))]
}

type Signature struct{}

var SIGN_KEY = []byte{
	0xDF, 0x77, 0xB9, 0x40, 0xB9, 0x9B, 0x84, 0x83, 0xD1, 0xB9,
	0xCB, 0xD1, 0xF7, 0xC2, 0xB9, 0x85, 0xC3, 0xD0, 0xFB, 0xC3,
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func swapNibbles(b byte) byte {
	return (b >> 4) | (b << 4)
}

func bitReverse8(x byte) byte {
	var y byte
	for i := 0; i < 8; i++ {
		if (x & (1 << i)) != 0 {
			y |= 1 << (7 - i)
		}
	}
	return y
}

func (s Signature) Generate(params, data, cookies string) map[string]string {
	g := md5Hex(params)
	if data != "" {
		g += md5Hex(data)
	} else {
		g += strings.Repeat("0", 32)
	}
	if cookies != "" {
		g += md5Hex(cookies)
	} else {
		g += strings.Repeat("0", 32)
	}
	g += strings.Repeat("0", 32)

	unixTs := uint32(time.Now().Unix())

	payload := make([]byte, 0, 20)

	for i := 0; i < 12; i += 4 {
		chunk := g[8*i : 8*(i+1)]
		for j := 0; j < 4; j++ {
			bHex := chunk[j*2 : (j+1)*2]
			v, _ := strconv.ParseUint(bHex, 16, 8)
			payload = append(payload, byte(v))
		}
	}

	payload = append(payload, 0x0, 0x6, 0xB, 0x1C)
	payload = append(payload, byte((unixTs&0xFF000000)>>24))
	payload = append(payload, byte((unixTs&0x00FF0000)>>16))
	payload = append(payload, byte((unixTs&0x0000FF00)>>8))
	payload = append(payload, byte(unixTs&0x000000FF))

	encrypted := make([]byte, len(payload))
	for i := 0; i < len(payload) && i < len(SIGN_KEY); i++ {
		encrypted[i] = payload[i] ^ SIGN_KEY[i]
	}

	for i := 0; i < 0x14 && i < len(encrypted); i++ {
		C := swapNibbles(encrypted[i])
		D := encrypted[(i+1)%len(encrypted)]
		F := bitReverse8(C ^ D)
		H := byte((^uint32(F) ^ 0x14) & 0xFF)
		encrypted[i] = H
	}

	buf := &bytes.Buffer{}
	for _, b := range encrypted {
		fmt.Fprintf(buf, "%02x", b)
	}

	return map[string]string{
		"X-Gorgon":  "840280416000" + buf.String(),
		"X-Khronos": fmt.Sprintf("%d", unixTs),
	}
}

// --- DANH SÁCH API MỚI ---
var apis = []string{
	"api16-core-c-alisg.tiktokv.com",
	"api16-core-c-useast1a.tiktokv.com",
	"api16-core-va.tiktokv.com",
	"api19-core-c-useast1a.tiktokv.com",
	"api19-core-va.tiktokv.com",
	"api19-normal-c-useast1a.tiktokv.com",
	"api21-core-c-alisg.tiktokv.com",
	"api22-core-c-useast1a.tiktokv.com",
	"api22-normal-c-useast1a.tiktokv.com",
}

var (
	totalViews   uint64 // Tổng số view được ghi nhận (từ tất cả các API)
	successful   uint64 // Tổng số yêu cầu thành công (từ tất cả các API)
	failed       uint64 // Tổng số yêu cầu thất bại (từ tất cả các API)
	retried      uint64 // Tổng số lần thử lại (từ tất cả các API)
	startTime    time.Time
	peakSpeed    float64
	lastUpdate   time.Time
	lastViews    uint64
)

func viewsPerSecond() float64 {
	now := time.Now()
	elapsed := now.Sub(startTime).Seconds()
	if elapsed <= 0 {
		return 0
	}
	v := float64(atomic.LoadUint64(&totalViews)) / elapsed
	if v > peakSpeed {
		peakSpeed = v
	}
	return v
}

func instantaneousSpeed() float64 {
	now := time.Now()
	elapsed := now.Sub(lastUpdate).Seconds()
	if elapsed <= 0 {
		return 0
	}
	newViews := atomic.LoadUint64(&totalViews) - lastViews
	return float64(newViews) / elapsed
}

func calculateStats() map[string]float64 {
	elapsed := time.Since(startTime).Seconds()
	vps := viewsPerSecond()
	instVPS := instantaneousSpeed()
	success := atomic.LoadUint64(&successful)
	fail := atomic.LoadUint64(&failed)
	retry := atomic.LoadUint64(&retried)
	total := success + fail
	successRate := 0.0
	if total > 0 {
		successRate = float64(success) / float64(total) * 100
	}
	return map[string]float64{
		"total_views":         float64(atomic.LoadUint64(&totalViews)),
		"elapsed_time":        elapsed,
		"views_per_second":    vps,
		"views_per_minute":    vps * 60,
		"views_per_hour":      vps * 3600,
		"instantaneous_vps":   instVPS,
		"success_rate":        successRate,
		"successful_requests": float64(success),
		"failed_requests":     float64(fail),
		"retried_requests":    float64(retry),
		"peak_speed":          peakSpeed,
	}
}

// Giao diện người dùng đơn giản nhưng rõ ràng
func printBanner() {
	fmt.Print("\033[H\033[2J") // Xóa màn hình
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   🚀 SPY VIEW BOT PRO - GO v2.2              ║")
	fmt.Println("║                 (Gửi đến tất cả API cùng lúc)                ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Nhanh hơn. Chính xác hơn. Giao diện đẹp hơn. (Không màu)    ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func printStats(stats map[string]float64) {
	// Giao diện trạng thái đơn giản, dễ đọc
	fmt.Printf("\r✅ Gửi: %.0f | Tốc độ: %.1f/s (%.1f/s) | Cao nhất: %.1f/s | TC: %.1f%% | TG: %.1fs",
		stats["total_views"],
		stats["views_per_second"], stats["instantaneous_vps"],
		stats["peak_speed"],
		stats["success_rate"],
		stats["elapsed_time"])
}

func getVideoIDFromURL(u string) string {
	patterns := []string{`/video/(\d+)`, `tiktok\.com/@[^/]+/(\d+)`, `(\d{18,19})`}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		m := re.FindStringSubmatch(u)
		if len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func getVideoID(u string) string {
	if id := getVideoIDFromURL(u); id != "" {
		return id
	}

	text, finalURL, err := fetchURL(u)
	if err != nil {
		return ""
	}

	if finalURL != "" {
		if id := getVideoIDFromURL(finalURL); id != "" {
			return id
		}
	}

	patterns := []string{
		`"video":\{"id":"(\d+)"`,
		`"videoId":"(\d+)"`,
		`"aweme_id":"(\d+)"`,
		`"id":"(\d{18,19})"`,
		`video/(\d+)`,
		`(\d{18,19})`,
		`"itemId":\s*"(\d+)"`,
		`"id":\s*(\d{18,19})`,
		`"aweme_id":\s*"(\d+)"`,
		`data-videoid="(\d+)"`,
		`videoId:\s*"(\d+)"`,
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		m := re.FindStringSubmatch(text)
		if len(m) > 1 {
			return m[1]
		}
	}

	reSigi := regexp.MustCompile(`(?s)SIGI_STATE.*?\{|window\.__INIT_PROPS__.*?\{|"aweme_id":"(\d+)"|"videoId":"(\d+)"`)
	if reSigi.MatchString(text) {
		reNum := regexp.MustCompile(`(\d{18,19})`)
		m2 := reNum.FindStringSubmatch(text)
		if len(m2) > 1 {
			return m2[1]
		}
	}

	return ""
}

func fetchURL(u string) (body string, finalURL string, err error) {
	tr := &http.Transport{
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxConnsPerHost:       200,
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	final := ""
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}

	max := int64(2 * 1024 * 1024)
	reader := io.LimitReader(resp.Body, max)
	b, _ := ioutil.ReadAll(reader)
	return string(b), final, nil
}

// Hàm tạo dữ liệu yêu cầu cho một API cụ thể
func generateRequestDataForAPI(videoID, apiHost string) (string, url.Values, map[string]string, map[string]string) {
	device := randomDevice()
	params := fmt.Sprintf("channel=googleplay&aid=1233&app_name=musical_ly&version_code=400304&device_platform=android&device_type=%s&os_version=%s&device_id=%d&os_api=%d&app_language=vi&tz_name=Asia%%2FHo_Chi_Minh",
		url.QueryEscape(device.Model), device.Version, rand.Intn(99999999999999)+600000000000000, device.ApiLevel)

	urlStr := "https://" + apiHost + "/aweme/v1/aweme/stats/?" + params

	data := url.Values{}
	data.Set("item_id", videoID)
	data.Set("play_delta", "1")
	data.Set("action_time", fmt.Sprintf("%d", time.Now().Unix()))

	cookies := map[string]string{
		"sessionid": fmt.Sprintf("%x", rand.Uint64()),
		"odin_tt":   fmt.Sprintf("%x", rand.Uint64()),
	}

	headers := map[string]string{
		"Content-Type":    "application/x-www-form-urlencoded; charset=UTF-8",
		"User-Agent":      "com.zhiliaoapp.musically/2023304030 (Linux; U; Android 13; en_US; Pixel 7 Pro; Build/TQ3A.230901.001;tt-ok/3.12.13.1)",
		"Accept-Encoding": "gzip",
		"Connection":      "keep-alive",
		"Host":            apiHost,
		"Accept":          "*/*",
	}

	return urlStr, data, cookies, headers
}

// Hàm gửi yêu cầu đến một API cụ thể
func sendViewRequestToAPI(client *http.Client, videoID, apiHost string) bool {
	urlStr, data, cookies, baseHeaders := generateRequestDataForAPI(videoID, apiHost)
	params := strings.SplitN(urlStr, "?", 2)
	paramsStr := ""
	if len(params) > 1 {
		paramsStr = params[1]
	}

	cookieStr := ""
	for k, v := range cookies {
		cookieStr += k + "=" + v + "; "
	}
	cookieStr = strings.TrimSuffix(cookieStr, "; ")

	sig := Signature{}.Generate(paramsStr, data.Encode(), cookieStr)

	reqBody := strings.NewReader(data.Encode())
	req, err := http.NewRequest("POST", urlStr, reqBody)
	if err != nil {
		atomic.AddUint64(&failed, 1)
		return false
	}

	for k, v := range baseHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range sig {
		req.Header.Set(k, v)
	}
	if cookieStr != "" {
		req.Header.Set("Cookie", cookieStr)
	}

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddUint64(&failed, 1)
		return false
	}
	defer resp.Body.Close()
	io.Copy(ioutil.Discard, resp.Body)

	if resp.StatusCode == 200 {
		// Nếu một trong các API trả về 200, coi như là một view thành công
		atomic.AddUint64(&totalViews, 1)
		atomic.AddUint64(&successful, 1)
		return true
	}
	atomic.AddUint64(&failed, 1)
	return false
}

// Hàm gửi yêu cầu đến tất cả các API cùng lúc
func sendViewRequestToAllAPIs(client *http.Client, videoID string) bool {
	var wg sync.WaitGroup
	var anySuccess int32 = 0 // Sử dụng atomic để ghi nhận nếu có ít nhất một API thành công

	for _, api := range apis {
		wg.Add(1)
		go func(apiHost string) {
			defer wg.Done()
			// Gửi yêu cầu với thử lại cho từng API riêng lẻ
			for attempt := 0; attempt <= MaxRetries; attempt++ {
				if sendViewRequestToAPI(client, videoID, apiHost) {
					atomic.StoreInt32(&anySuccess, 1) // Ghi nhận thành công
					return // Thoát khỏi goroutine nếu thành công
				}
				if attempt < MaxRetries {
					atomic.AddUint64(&retried, 1)
					time.Sleep(time.Duration(50+rand.Intn(100)) * time.Millisecond)
				}
			}
		}(api)
	}

	wg.Wait() // Chờ tất cả các goroutine gửi yêu cầu hoàn thành

	return atomic.LoadInt32(&anySuccess) == 1 // Trả về true nếu có ít nhất một API thành công
}

func worker(ctx context.Context, wg *sync.WaitGroup, client *http.Client, videoID string, semaphore chan struct{}) {
	defer wg.Done()
	consecutiveSuccess := 0
	consecutiveFail := 0
	baseDelay := time.Duration(InitialDelayMs) * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return
		case semaphore <- struct{}{}:
		}

		// Gửi đến tất cả API cùng lúc
		success := sendViewRequestToAllAPIs(client, videoID)
		<-semaphore

		if success {
			consecutiveSuccess++
			consecutiveFail = 0
		} else {
			consecutiveFail++
			consecutiveSuccess = 0
		}

		delay := baseDelay
		if consecutiveSuccess > MaxConsecutiveSuccess {
			delay = time.Duration(float64(baseDelay) * 0.3)
		} else if consecutiveSuccess > 100 {
			delay = time.Duration(float64(baseDelay) * 0.5)
		} else if consecutiveSuccess > 50 {
			delay = time.Duration(float64(baseDelay) * 0.7)
		}

		if consecutiveFail > MinConsecutiveFail {
			delay = time.Duration(float64(delay) * 3.0)
		} else if consecutiveFail > 2 {
			delay = time.Duration(float64(delay) * 2.0)
		}

		vps := viewsPerSecond()
		if vps > 1500 {
			delay = time.Duration(float64(delay) * 2.5)
		} else if vps > 1000 {
			delay = time.Duration(float64(delay) * 2.0)
		} else if vps > 500 {
			delay = time.Duration(float64(delay) * 1.5)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay + time.Duration(rand.Intn(5))*time.Millisecond):
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	printBanner()

	workersEnv := os.Getenv("WORKERS")
	concurrencyEnv := os.Getenv("CONCURRENCY")
	timeoutEnv := os.Getenv("TIMEOUT")

	defaultWorkers := 2000
	defaultConcurrency := 1500 // Chú ý: Số lượng đồng thời sẽ ảnh hưởng mạnh hơn khi mỗi worker gửi đến nhiều API
	defaultTimeout := 35

	if workersEnv != "" {
		if n, e := strconv.Atoi(workersEnv); e == nil && n > 0 {
			defaultWorkers = n
		}
	}
	if concurrencyEnv != "" {
		if n, e := strconv.Atoi(concurrencyEnv); e == nil && n > 0 {
			defaultConcurrency = n
		}
	}
	if timeoutEnv != "" {
		if n, e := strconv.Atoi(timeoutEnv); e == nil && n > 0 {
			defaultTimeout = n
		}
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("📥 Vui lòng nhập URL video TikTok: ")
	urlStr, _ := reader.ReadString('\n')
	urlStr = strings.TrimSpace(urlStr)
	if urlStr == "" || !(strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://")) {
		fmt.Println("❌ Định dạng URL không hợp lệ!")
		return
	}

	fmt.Println("🔄 Kiểm tra kết nối mạng...")
	resp, err := http.Get("https://www.google.com")
	if err != nil || resp.StatusCode != 200 {
		fmt.Println("❌ Không có kết nối internet!")
		return
	}
	resp.Body.Close()

	fmt.Println("🔄 Đang trích xuất ID video...")
	videoID := getVideoID(urlStr)
	if videoID == "" {
		fmt.Println("❌ Không thể tìm thấy ID video!")
		return
	}
	fmt.Printf("✅ ID Video: %s\n", videoID)

	cpuCount := runtime.NumCPU()
	var optimalWorkers int
	if defaultWorkers > 0 {
		optimalWorkers = defaultWorkers
	} else {
		if cpuCount <= 2 {
			optimalWorkers = 800
		} else if cpuCount <= 4 {
			optimalWorkers = 1500
		} else if cpuCount <= 8 {
			optimalWorkers = 2500
		} else {
			optimalWorkers = 4000
		}
	}

	// Cảnh báo nếu số lượng đồng thời quá cao so với số API
	if defaultConcurrency*len(apis) > 10000 { // Ngưỡng tùy chọn
		fmt.Printf("⚠️  Cảnh báo: Số lượng yêu cầu đồng thời cao (%d x %d APIs = %d). Có thể ảnh hưởng hiệu năng hoặc bị chặn IP.\n", defaultConcurrency, len(apis), defaultConcurrency*len(apis))
		time.Sleep(3 * time.Second) // Tạm dừng để người dùng đọc cảnh báo
	}

	fmt.Printf("🎯 Bắt đầu với khoảng %d workers (đồng thời=%d, tổng đồng thời tiềm năng=%d)\n", optimalWorkers, defaultConcurrency, defaultConcurrency*len(apis))

	startTime = time.Now()
	lastUpdate = startTime
	lastViews = 0

	tr := &http.Transport{
		MaxIdleConns:          10000 * len(apis), // Tăng số lượng kết nối tối đa theo số lượng API
		MaxIdleConnsPerHost:   1000,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxConnsPerHost:       500,
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(defaultTimeout) * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		fmt.Println("\n\n🛑 Nhận tín hiệu dừng, đang tắt chương trình...")
		cancel()
	}()

	semaphore := make(chan struct{}, defaultConcurrency)
	wg := &sync.WaitGroup{}
	for i := 0; i < optimalWorkers; i++ {
		wg.Add(1)
		go worker(ctx, wg, client, videoID, semaphore)
	}

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := calculateStats()
				printStats(stats)
				lastUpdate = time.Now()
				lastViews = atomic.LoadUint64(&totalViews)
			}
		}
	}()

	wg.Wait()
	fmt.Println("\n\n🛑 Tất cả các worker đã hoàn thành.")

	finalStats := calculateStats()
	fmt.Printf("\n📊 Thống kê cuối cùng:\n")
	fmt.Printf("   Tổng View: %.0f\n", finalStats["total_views"])
	fmt.Printf("   Tốc độ TB: %.1f view/s\n", finalStats["views_per_second"])
	fmt.Printf("   Tốc độ Cao Nhất: %.1f view/s\n", finalStats["peak_speed"])
	fmt.Printf("   Tỷ Lệ Thành Công: %.1f%%\n", finalStats["success_rate"])
	fmt.Printf("   Tổng Thời Gian: %.1fs\n", finalStats["elapsed_time"])
	fmt.Printf("   Số Lần Thử Lại: %.0f\n", finalStats["retried_requests"])
}