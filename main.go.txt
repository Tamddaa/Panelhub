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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// A compact translation of viewv3.1.py functionality into Go.
// This implementation focuses on behavior parity: video ID extraction,
// signature generation (X-Gorgon/X-Khronos), concurrent POST requests,
// adaptive delay and basic statistics tracking.

type DeviceInfo struct {
	Model    string
	Version  string
	ApiLevel int
}

var devices = []DeviceInfo{
	{"Pixel 6", "12", 31},
	{"Pixel 5", "11", 30},
	{"Samsung Galaxy S21", "13", 33},
	{"Oppo Reno 8", "12", 31},
	{"Xiaomi Mi 11", "12", 31},
}

func randomDevice() DeviceInfo {
	return devices[rand.Intn(len(devices))]
}

// Signature generation ported from Python logic.
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

	// Mirror python loop: for i in range(0,12,4): i = 0,4,8
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

	// XOR with key
	encrypted := make([]byte, len(payload))
	for i := 0; i < len(payload) && i < len(SIGN_KEY); i++ {
		encrypted[i] = payload[i] ^ SIGN_KEY[i]
	}

	// Transform
	for i := 0; i < 0x14 && i < len(encrypted); i++ {
		C := swapNibbles(encrypted[i])
		D := encrypted[(i+1)%len(encrypted)]
		F := bitReverse8(C ^ D)
		// ((F ^ 0xFFFFFFFF) ^ 0x14) & 0xFF  -> (~F ^ 0x14) & 0xFF
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

// Stats and counters
var totalViews uint64
var successful uint64
var failed uint64
var startTime time.Time
var peakSpeed float64

func viewsPerSecond() float64 {
	elapsed := time.Since(startTime).Seconds()
	if elapsed <= 0 {
		return 0
	}
	v := float64(atomic.LoadUint64(&totalViews)) / elapsed
	// update peak
	if v > peakSpeed {
		peakSpeed = v
	}
	return v
}

func calculateStats() map[string]float64 {
	elapsed := time.Since(startTime).Seconds()
	vps := viewsPerSecond()
	success := atomic.LoadUint64(&successful)
	fail := atomic.LoadUint64(&failed)
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
		"success_rate":        successRate,
		"successful_requests": float64(success),
		"failed_requests":     float64(fail),
		"peak_speed":          peakSpeed,
	}
}

func printBanner() {
	fmt.Print("\033[H\033[2J")
	fmt.Println("╔════════════════════════════════════════════════════╗")
	fmt.Println("║              🚀 SPY VIEW BOT PRO - GO              ║")
	fmt.Println("╠════════════════════════════════════════════════════╣")
	fmt.Println("║  Fast. Configurable. Improved ID detection.        ║")
	fmt.Println("╚════════════════════════════════════════════════════╝")
	fmt.Println()
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
	// 1) Try direct URL patterns first
	if id := getVideoIDFromURL(u); id != "" {
		return id
	}

	// 2) Fetch page and follow redirects, using a stronger client and UA
	text, finalURL, err := fetchURL(u)
	if err != nil {
		return ""
	}

	// 3) Check final URL after redirects
	if finalURL != "" {
		if id := getVideoIDFromURL(finalURL); id != "" {
			return id
		}
	}

	// 4) Scan HTML/JSON body for many common patterns
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
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		m := re.FindStringSubmatch(text)
		if len(m) > 1 {
			return m[1]
		}
	}

	// 5) fallback: attempt to find JSON blocks like SIGI_STATE and parse
	reSigi := regexp.MustCompile(`(?s)SIGI_STATE.*?\{|window\.__INIT_PROPS__.*?\{|"aweme_id":"(\d+)"|"videoId":"(\d+)"`)
	if reSigi.MatchString(text) {
		// try simple numeric search
		reNum := regexp.MustCompile(`(\d{18,19})`)
		m2 := reNum.FindStringSubmatch(text)
		if len(m2) > 1 {
			return m2[1]
		}
	}

	return ""
}

// fetchURL gets the body (as string) and final URL after redirects using a tuned client
func fetchURL(u string) (body string, finalURL string, err error) {
	tr := &http.Transport{
		MaxIdleConns:          10000,
		MaxIdleConnsPerHost:   10000,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	final := ""
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}

	max := int64(1024 * 1024) // 1MB
	reader := io.LimitReader(resp.Body, max)
	b, _ := ioutil.ReadAll(reader)
	return string(b), final, nil
}

func generateRequestData(videoID string) (string, url.Values, map[string]string, map[string]string) {
	device := randomDevice()
	params := fmt.Sprintf("channel=googleplay&aid=1233&app_name=musical_ly&version_code=400304&device_platform=android&device_type=%s&os_version=%s&device_id=%d&os_api=%d&app_language=vi&tz_name=Asia%%2FHo_Chi_Minh",
		strings.ReplaceAll(device.Model, " ", "+"), device.Version, rand.Intn(99999999999999)+600000000000000, device.ApiLevel)

	urlStr := "https://api16-core-c-alisg.tiktokv.com/aweme/v1/aweme/stats/?" + params

	data := url.Values{}
	data.Set("item_id", videoID)
	data.Set("play_delta", "1")
	data.Set("action_time", fmt.Sprintf("%d", time.Now().Unix()))

	cookies := map[string]string{"sessionid": fmt.Sprintf("%x", rand.Uint64())}

	headers := map[string]string{
		"Content-Type":    "application/x-www-form-urlencoded; charset=UTF-8",
		"User-Agent":      "com.ss.android.ugc.trill/400304",
		"Accept-Encoding": "gzip",
		"Connection":      "keep-alive",
	}

	return urlStr, data, cookies, headers
}

func sendViewRequest(client *http.Client, videoID string) bool {
	urlStr, data, cookies, baseHeaders := generateRequestData(videoID)
	params := strings.SplitN(urlStr, "?", 2)
	paramsStr := ""
	if len(params) > 1 {
		paramsStr = params[1]
	}

	// build cookies string
	cookieStr := ""
	for k, v := range cookies {
		cookieStr += k + "=" + v + ";"
	}

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
	// set cookies header
	if cookieStr != "" {
		req.Header.Set("Cookie", cookieStr)
	}

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddUint64(&failed, 1)
		return false
	}
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 200 {
		atomic.AddUint64(&totalViews, 1)
		atomic.AddUint64(&successful, 1)
		return true
	}
	atomic.AddUint64(&failed, 1)
	return false
}

func worker(ctx context.Context, wg *sync.WaitGroup, client *http.Client, videoID string, semaphore chan struct{}) {
	defer wg.Done()
	consecutive := 0
	baseDelay := 1 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return
		case semaphore <- struct{}{}:
			// acquired slot
		}

		success := sendViewRequest(client, videoID)
		<-semaphore // release

		if success {
			consecutive++
		} else {
			consecutive = 0
		}

		delay := baseDelay
		if consecutive > 100 {
			delay = time.Duration(float64(baseDelay) * 0.5)
		} else if consecutive > 50 {
			delay = time.Duration(float64(baseDelay) * 0.7)
		}

		vps := viewsPerSecond()
		if vps > 1000 {
			delay *= 2
		} else if vps > 500 {
			delay = time.Duration(float64(delay) * 1.5)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay + time.Duration(rand.Intn(3))*time.Millisecond):
			// continue
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	printBanner()
	// Config via environment variables (WORKERS, CONCURRENCY, TIMEOUT) for simpler usage in containers
	// Defaults tuned for higher throughput; change via environment when needed.
	workersEnv := os.Getenv("WORKERS")
	concurrencyEnv := os.Getenv("CONCURRENCY")
	timeoutEnv := os.Getenv("TIMEOUT")

	// default values
	defaultWorkers := 1000
	defaultConcurrency := 800
	defaultTimeout := 30

	// parse env values if provided
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

	// Read URL from stdin
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("📥 Please enter Spy video URL: ")
	urlStr, _ := reader.ReadString('\n')
	urlStr = strings.TrimSpace(urlStr)
	if urlStr == "" || !(strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://")) {
		fmt.Println("❌ Invalid URL format")
		return
	}

	// quick connectivity check
	_, err := http.Get("https://www.google.com")
	if err != nil {
		fmt.Println("❌ No internet connection")
		return
	}

	fmt.Println("🔄 Getting Video ID...")
	videoID := getVideoID(urlStr)
	if videoID == "" {
		fmt.Println("❌ Could not find video ID")
		return
	}
	fmt.Printf("✅ Video ID: %s\n", videoID)

	// determine workers: prefer CLI flag, otherwise basic CPU heuristic
	cpuCount := 1
	if v := os.Getenv("CPU_COUNT"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			cpuCount = n
		}
	}
	if cpuCount <= 0 {
		cpuCount = 1
	}

	var optimalWorkers int
	if defaultWorkers > 0 {
		optimalWorkers = defaultWorkers
	} else {
		if cpuCount <= 2 {
			optimalWorkers = 400
		} else if cpuCount <= 4 {
			optimalWorkers = 1000
		} else {
			optimalWorkers = 2000
		}
	}

	fmt.Printf("🎯 Starting approx %d workers (concurrency=%d)\n", optimalWorkers, defaultConcurrency)

	startTime = time.Now()

	tr := &http.Transport{
		MaxIdleConns:          10000,
		MaxIdleConnsPerHost:   10000,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(defaultTimeout) * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		fmt.Println("\n🛑 Received stop signal, shutting down...")
		cancel()
	}()

	semaphore := make(chan struct{}, defaultConcurrency) // limit concurrent HTTP in-flight
	wg := &sync.WaitGroup{}
	for i := 0; i < optimalWorkers; i++ {
		wg.Add(1)
		go worker(ctx, wg, client, videoID, semaphore)
	}

	// monitor
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := calculateStats()
				fmt.Printf("\r✅ Sent: %.0f | Speed: %.1f view/s | Peak: %.1f view/s | Success: %.1f%% | Time: %.1fs",
					stats["total_views"], stats["views_per_second"], stats["peak_speed"], stats["success_rate"], stats["elapsed_time"])
			}
		}
	}()

	wg.Wait()
	fmt.Println("\n🛑 All workers finished")
	stats := calculateStats()
	fmt.Printf("\nFinal stats: Total=%.0f, SuccessRate=%.1f%%, Elapsed=%.1fs\n", stats["total_views"], stats["success_rate"], stats["elapsed_time"])
}
