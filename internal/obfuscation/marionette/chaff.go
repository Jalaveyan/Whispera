package marionette

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

type ChaffGenerator struct {
	Enabled      bool
	Targets      []string
	MinInterval  time.Duration
	MaxInterval  time.Duration
	Concurrency  int
	DirectDialer *net.Dialer
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewChaffGenerator() *ChaffGenerator {
	return &ChaffGenerator{
		Enabled: true,
		Targets: []string{
			"www.google.com:443",
			"www.microsoft.com:443",
			"www.twitch.tv:443",

			"vk.com:443",
			"dzen.ru:443",
			"www.ozon.ru:443",
			"www.wildberries.ru:443",
			"rutube.ru:443",
			"yandex.ru:443",
			"mail.ru:443",
			"disk.yandex.ru:443",
			"ok.ru:443",
			"www.gosuslugi.ru:443",
		},
		MinInterval: 30 * time.Second,
		MaxInterval: 120 * time.Second,
		Concurrency: 1,
		DirectDialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}

func (cg *ChaffGenerator) Start() {
	if !cg.Enabled {
		return
	}
	cg.ctx, cg.cancel = context.WithCancel(context.Background())

	for i := 0; i < cg.Concurrency; i++ {
		go cg.loop()
	}
}

func (cg *ChaffGenerator) Stop() {
	if cg.cancel != nil {
		cg.cancel()
	}
}

func (cg *ChaffGenerator) loop() {
	for {
		intervalRange := int64(cg.MaxInterval - cg.MinInterval)
		randomDelay := cg.MinInterval + time.Duration(rand.Int63n(intervalRange))

		select {
		case <-cg.ctx.Done():
			return
		case <-time.After(randomDelay):
			cg.spawnChaff()
		}
	}
}

func (cg *ChaffGenerator) spawnChaff() {
	idx := rand.Intn(len(cg.Targets))
	target := cg.Targets[idx]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := cg.DirectDialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer conn.Close()

	var helloID utls.ClientHelloID
	r := rand.Intn(3)
	switch r {
	case 0:
		helloID = utls.HelloChrome_Auto
	case 1:
		helloID = utls.HelloFirefox_Auto
	case 2:
		helloID = utls.HelloIOS_Auto
	}

	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         splitHost(target),
		InsecureSkipVerify: true,
		MinVersion:         utls.VersionTLS12,
		MaxVersion:         utls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
	}, helloID)

	uConn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := uConn.Handshake(); err != nil {
		return
	}

	negotiatedProto := uConn.ConnectionState().NegotiatedProtocol

	if negotiatedProto == "h2" {
		cg.sendHTTP2Request(uConn, target)
	} else {
		cg.sendHTTP11Request(uConn, target)
	}
}

func (cg *ChaffGenerator) sendHTTP2Request(conn net.Conn, target string) {
	hostname := splitHost(target)

	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+hostname+"/", nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,ru;q=0.8")
	req.Header.Set("Cache-Control", "max-age=0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)
}

func (cg *ChaffGenerator) sendHTTP11Request(conn net.Conn, target string) {
	hostname := splitHost(target)

	headers := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"+
			"Accept-Language: en-US,en;q=0.9,ru;q=0.8\r\n"+
			"\r\n",
		hostname)

	conn.Write([]byte(headers))

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}
}

func splitHost(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
