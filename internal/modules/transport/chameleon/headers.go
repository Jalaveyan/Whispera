package chameleon

import (
	"math/rand"
	"net/http"
)

// mobileUserAgents — pool of real Android Chrome UAs sampled from browser telemetry.
var mobileUserAgents = []string{
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.53 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.179 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.99 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; Redmi Note 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; M2101K6G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.53 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.179 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; moto g82 5G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.99 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; CPH2609) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
}

// acceptLanguages — common Accept-Language values weighted by global usage.
var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9",
	"ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
	"de-DE,de;q=0.9,en;q=0.8",
	"fr-FR,fr;q=0.9,en;q=0.8",
	"tr-TR,tr;q=0.9,en;q=0.8",
	"uk-UA,uk;q=0.9,ru;q=0.8,en;q=0.7",
	"zh-CN,zh;q=0.9,en;q=0.8",
	"es-ES,es;q=0.9,en;q=0.8",
	"ar-SA,ar;q=0.9,en;q=0.8",
}

// applyBrowserHeaders adds realistic Chrome-on-Android request headers.
// origin is the https://host value used for Origin and Referer.
func applyBrowserHeaders(req *http.Request, origin string) {
	ua := mobileUserAgents[rand.Intn(len(mobileUserAgents))]
	lang := acceptLanguages[rand.Intn(len(acceptLanguages))]

	// Chrome version extracted from UA for Sec-CH-UA.
	// Keep it in sync with the selected UA.
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", lang)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	// Fetch metadata — mirrors what Chrome sends for cross-origin fetch().
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")

	// Connection — kept alive by HTTP/2 by default, but set for completeness.
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
}
