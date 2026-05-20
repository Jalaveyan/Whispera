//go:build linux

package ml

import (
	"context"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"time"
)

var simUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
}

// pageBrowseTargets — страницы для симуляции просмотра сайтов.
var pageBrowseTargets = []struct {
	host  string
	paths []string
}{
	{"vk.com", []string{"/feed", "/video", "/clips"}},
	{"ok.ru", []string{"/", "/video"}},
	{"rutube.ru", []string{"/", "/trending/"}},
	{"music.yandex.ru", []string{"/"}},
	{"www.ivi.ru", []string{"/", "/movies/"}},
}

// audioStreamProfile описывает HLS аудио сегменты.
// Яндекс.Музыка / VK Music: 128kbps AAC, сегменты ~10s = ~160KB.
// CDN отдаёт большими TCP сегментами — референсный паттерн для аудио стриминга.
type audioProfile struct {
	cdnHost     string
	segmentPath string        // шаблон пути, %d подставляется как номер сегмента
	segmentSize int64         // типичный размер сегмента в байтах
	segInterval time.Duration // реальное время между сегментами
	segCount    int           // сегментов за сессию
	accept      string
	referer     string
}

var audioProfiles = []audioProfile{
	// Яндекс.Музыка CDN — audio/mp4 сегменты через yastatic CDN.
	{
		cdnHost:     "yastatic.net",
		segmentPath: "/s3/music-home-static/static/p/yandex-music-web-player/main.js",
		segmentSize: 180 * 1024,
		segInterval: 10 * time.Second,
		segCount:    8,
		accept:      "audio/webm,audio/ogg,audio/wav,audio/*;q=0.9,*/*;q=0.8",
		referer:     "https://music.yandex.ru/",
	},
	// VK Музыка CDN — audio через cs.userapi.com.
	{
		cdnHost:     "cs.userapi.com",
		segmentPath: "/c235131/v235131946/1a3f3/lLHfYHYmhcw.jpg",
		segmentSize: 200 * 1024,
		segInterval: 9 * time.Second,
		segCount:    6,
		accept:      "audio/mpeg,audio/*;q=0.9,*/*;q=0.8",
		referer:     "https://vk.com/",
	},
}

// videoStreamProfile описывает HLS видео сегменты.
// VK Video / Rutube 720p: ~1Mbps, сегменты ~2s = ~250KB.
// Более высокий битрейт → более насыщенный MTU-паттерн.
type videoProfile struct {
	cdnHost     string
	paths       []string
	segmentSize int64
	segInterval time.Duration
	segCount    int
	accept      string
	referer     string
}

var videoProfiles = []videoProfile{
	// VK Video CDN — video/mp4 через vkvideo.ru CDN.
	{
		cdnHost: "st.vk.com",
		paths: []string{
			"/depot/webpack/_/bundles/main.js",
			"/depot/webpack/_/bundles/common.js",
		},
		segmentSize: 900 * 1024,
		segInterval: 2500 * time.Millisecond,
		segCount:    12,
		accept:      "video/webm,video/mp4,video/*;q=0.9,*/*;q=0.8",
		referer:     "https://vk.com/video",
	},
	// Rutube CDN.
	{
		cdnHost: "yastatic.net",
		paths: []string{
			"/s3/home/_/54/_/Xq2AAAAAAAAA.js",
			"/s3/home-promo/_/q3/3b2c9e31a3c3.js",
		},
		segmentSize: 1200 * 1024,
		segInterval: 2 * time.Second,
		segCount:    10,
		accept:      "video/webm,video/mp4,video/*;q=0.9,*/*;q=0.8",
		referer:     "https://rutube.ru/",
	},
}

// RunBrowserSim запускает три параллельных симулятора:
//  1. Page browsing — случайные переходы по страницам (VK, OK, Rutube).
//  2. Audio streaming — Яндекс.Музыка / VK Music (HLS аудио сегменты).
//  3. Video streaming — VK Video / Rutube (HLS видео сегменты).
//
// Все соединения регистрируются как FlowDecoy → pcap_collector кормит
// GlobalFlowObserver.UpdateReference() реальными измерениями с CDN.
func RunBrowserSim(ctx context.Context) {
	client := newSimClient()
	go runPageBrowsing(ctx, client)
	go runAudioStreaming(ctx, newSimClient())
	go runVideoStreaming(ctx, newSimClient())
	<-ctx.Done()
}

// runPageBrowsing периодически открывает страницы — браузерный page-load паттерн.
func runPageBrowsing(ctx context.Context, client *http.Client) {
	for {
		delay := jitter(30*time.Second, 0.5)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		t := pageBrowseTargets[mrand.Intn(len(pageBrowseTargets))]
		path := t.paths[mrand.Intn(len(t.paths))]
		fetchDecoy(ctx, client, t.host, path,
			"text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
			"", 256*1024)
	}
}

// runAudioStreaming симулирует непрерывное воспроизведение музыки:
// каждые ~10 секунд запрашивает следующий аудио сегмент (~160-200KB).
func runAudioStreaming(ctx context.Context, client *http.Client) {
	// Случайная начальная задержка чтобы не все симуляторы стартовали одновременно.
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter(5*time.Second, 0.8)):
	}

	for {
		p := audioProfiles[mrand.Intn(len(audioProfiles))]
		// Одна "сессия прослушивания" — несколько сегментов подряд.
		for i := 0; i < p.segCount; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			fetchDecoy(ctx, client, p.cdnHost, p.segmentPath,
				p.accept, p.referer, p.segmentSize)

			// Пауза между сегментами = реальное время воспроизведения ± 15%.
			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter(p.segInterval, 0.15)):
			}
		}
		// Пауза между треками (смена песни) — 3-8 секунд.
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(5*time.Second, 0.5)):
		}
	}
}

// runVideoStreaming симулирует просмотр видео:
// каждые ~2 секунды запрашивает следующий видео сегмент (~900KB-1.2MB).
// Это самый важный паттерн для референса: максимальная насыщенность MTU.
func runVideoStreaming(ctx context.Context, client *http.Client) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter(15*time.Second, 0.8)):
	}

	for {
		p := videoProfiles[mrand.Intn(len(videoProfiles))]
		path := p.paths[mrand.Intn(len(p.paths))]

		for i := 0; i < p.segCount; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			fetchDecoy(ctx, client, p.cdnHost, path,
				p.accept, p.referer, p.segmentSize)

			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter(p.segInterval, 0.15)):
			}
		}
		// Пауза между видео (реклама / буферизация) — 5-20 секунд.
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(12*time.Second, 0.6)):
		}
	}
}

func fetchDecoy(ctx context.Context, client *http.Client, host, path, accept, referer string, limit int64) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+host+path, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", simUserAgents[mrand.Intn(len(simUserAgents))])
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	resp.Body.Close()
}

func newSimClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(dialCtx, network, addr)
				if err != nil {
					return nil, err
				}
				FlowRegistry.RegisterConn(conn.LocalAddr(), conn.RemoteAddr(), FlowDecoy)
				return &simConn{Conn: conn}, nil
			},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       90 * time.Second,
		},
		Timeout: 45 * time.Second,
	}
}

// jitter возвращает d ± fraction*d для избежания фиксированного fingerprint.
func jitter(d time.Duration, fraction float64) time.Duration {
	delta := float64(d) * fraction
	return time.Duration(float64(d) - delta + mrand.Float64()*2*delta)
}

// simConn deregisters the flow from FlowRegistry when the TCP connection closes.
type simConn struct{ net.Conn }

func (c *simConn) Close() error {
	FlowRegistry.DeleteConn(c.Conn.LocalAddr(), c.Conn.RemoteAddr())
	return c.Conn.Close()
}
