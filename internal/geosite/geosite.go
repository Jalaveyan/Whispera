package geosite

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

type GeoSiteDatabase struct {
	domains map[string][]string
	mu      sync.RWMutex
}

func NewGeoSiteDatabase() *GeoSiteDatabase {
	return &GeoSiteDatabase{
		domains: make(map[string][]string),
	}
}

func (db *GeoSiteDatabase) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open geosite file: %w", err)
	}
	defer file.Close()

	db.mu.Lock()
	defer db.mu.Unlock()

	db.domains = make(map[string][]string)

	header := make([]byte, 12)
	if _, err := io.ReadFull(file, header); err != nil {
		if err == io.EOF {
			return db.loadSimpleFormat(file)
		}
		return fmt.Errorf("failed to read header: %w", err)
	}

	magic := string(header[:4])
	if magic != "v2rs" {
		return db.loadSimpleFormat(file)
	}

	_ = binary.BigEndian.Uint32(header[4:8])

	count := binary.BigEndian.Uint32(header[8:12])

	loadedCountries := 0
	for i := uint32(0); i < count; i++ {
		ccLenBytes := make([]byte, 1)
		if _, err := io.ReadFull(file, ccLenBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		ccLen := int(ccLenBytes[0])

		if ccLen == 0 || ccLen > 50 {
			continue
		}
		ccBytes := make([]byte, ccLen)
		if _, err := io.ReadFull(file, ccBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		countryCode := string(ccBytes)

		domainCountBytes := make([]byte, 4)
		if _, err := io.ReadFull(file, domainCountBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		domainCount := binary.BigEndian.Uint32(domainCountBytes)

		var domains []string
		for j := uint32(0); j < domainCount; j++ {
			domainLenBytes := make([]byte, 1)
			if _, err := io.ReadFull(file, domainLenBytes); err != nil {
				if err == io.EOF {
					break
				}
				continue
			}
			domainLen := int(domainLenBytes[0])

			if domainLen == 0 || domainLen > 255 {
				continue
			}
			domainBytes := make([]byte, domainLen)
			if _, err := io.ReadFull(file, domainBytes); err != nil {
				if err == io.EOF {
					break
				}
				continue
			}
			domain := string(domainBytes)

			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain != "" {
				domains = append(domains, domain)
			}
		}

		if len(domains) > 0 {
			if existing, ok := db.domains[countryCode]; ok {
				db.domains[countryCode] = append(existing, domains...)
			} else {
				db.domains[countryCode] = domains
			}
			loadedCountries++
		}
	}

	if loadedCountries == 0 {
		return db.loadSimpleFormat(file)
	}

	return nil
}

func (db *GeoSiteDatabase) loadSimpleFormat(file *os.File) error {
	file.Seek(0, 0)
	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	currentCountry := ""
	loadedCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			currentCountry = strings.ToLower(strings.TrimSpace(parts[0]))
			if len(parts) > 1 {
				domain := strings.ToLower(strings.TrimSpace(parts[1]))
				if domain != "" && currentCountry != "" {
					if db.domains[currentCountry] == nil {
						db.domains[currentCountry] = []string{}
					}
					db.domains[currentCountry] = append(db.domains[currentCountry], domain)
					loadedCount++
				}
			}
		} else if currentCountry != "" {
			domain := strings.ToLower(strings.TrimSpace(line))
			if domain != "" {
				if db.domains[currentCountry] == nil {
					db.domains[currentCountry] = []string{}
				}
				db.domains[currentCountry] = append(db.domains[currentCountry], domain)
				loadedCount++
			}
		}
	}

	if loadedCount == 0 {
		return fmt.Errorf("no valid entries found in file")
	}

	return nil
}

func (db *GeoSiteDatabase) GetDomains(countryCode string) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	countryCode = strings.ToLower(strings.TrimSpace(countryCode))
	domains, ok := db.domains[countryCode]
	if !ok {
		return nil
	}

	result := make([]string, len(domains))
	copy(result, domains)
	return result
}

func (db *GeoSiteDatabase) GetCategories(countryCode string) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	countryCode = strings.ToLower(strings.TrimSpace(countryCode))
	prefix := countryCode + ":category:"

	var categories []string
	for key := range db.domains {
		if strings.HasPrefix(key, prefix) {
			category := strings.TrimPrefix(key, prefix)
			if category != "" {
				categories = append(categories, category)
			}
		}
	}

	return categories
}

func (db *GeoSiteDatabase) GetAllCountries() []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	countries := make([]string, 0, len(db.domains))
	for country := range db.domains {
		countries = append(countries, country)
	}
	return countries
}

func (db *GeoSiteDatabase) IsDomainInCategory(domain, category string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	category = strings.ToLower(strings.TrimSpace(category))
	domains, ok := db.domains[category]
	if !ok {
		return false
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	domain = strings.TrimPrefix(domain, ".")

	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}

		if d == domain || strings.HasSuffix(domain, "."+d) {
			return true
		}

		if strings.HasPrefix(d, ".") {
			wildcard := d[1:]
			if domain == wildcard || strings.HasSuffix(domain, "."+wildcard) {
				return true
			}
		}
	}

	return false
}

func (db *GeoSiteDatabase) IsDomainInCountry(domain, countryCode string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	domains, ok := db.domains[countryCode]
	if !ok {
		return false
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	domain = strings.TrimPrefix(domain, ".")

	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}

		if d == domain {
			return true
		}
		if strings.HasSuffix(domain, "."+d) {
			return true
		}
		if strings.HasPrefix(d, ".") {
			wildcard := d[1:]
			if domain == wildcard || strings.HasSuffix(domain, "."+wildcard) {
				return true
			}
		}

		if strings.HasPrefix(d, ".") {
			if strings.HasSuffix(domain, d) {
				return true
			}
		}
	}

	return false
}

func DownloadGeoSite(url string, outputPath string) error {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download geosite: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download geosite: status %d", resp.StatusCode)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
