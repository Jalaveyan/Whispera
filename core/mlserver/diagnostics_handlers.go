package mlserver

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

func (s *MLServer) handleScan(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "127.0.0.1"
	}

	ports := map[int]string{
		22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 993: "IMAPS",
		1080: "SOCKS", 1194: "OpenVPN", 3128: "Proxy", 5222: "XMPP",
		8080: "HTTP-Alt", 8443: "Whispera", 9050: "Tor", 4443: "HTTPS-Alt",
		51820: "WireGuard",
	}

	type scanResult struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Open    bool   `json:"open"`
		Service string `json:"service"`
		Latency int    `json:"latency"`
	}

	var results []scanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for port, svc := range ports {
		wg.Add(1)
		go func(p int, service string) {
			defer wg.Done()
			start := time.Now()
			conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
			elapsed := time.Since(start)
			open := err == nil
			var lat int
			if open {
				conn.Close()
				lat = int(elapsed.Milliseconds())
				if lat == 0 {
					lat = 1
				}
			}
			mu.Lock()
			results = append(results, scanResult{
				Host: host, Port: p, Open: open, Service: service, Latency: lat,
			})
			mu.Unlock()
		}(port, svc)
	}
	wg.Wait()

	s.addLogf("scan %s: %d ports checked", host, len(ports))
	s.jsonReply(w, map[string]interface{}{"results": results})
}

func (s *MLServer) handleSelfTest(w http.ResponseWriter, r *http.Request) {
	s.jsonReply(w, s.engine.SelfTest())
}
