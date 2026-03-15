package geoip

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

type GeoIPDatabase struct {
	ipv4CIDRs map[string]string 
	ipv6CIDRs map[string]string 
	mu        sync.RWMutex
}

func NewGeoIPDatabase() *GeoIPDatabase {
	return &GeoIPDatabase{
		ipv4CIDRs: make(map[string]string),
		ipv6CIDRs: make(map[string]string),
	}
}
func (db *GeoIPDatabase) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open geoip file: %w", err)
	}
	defer file.Close()

	db.mu.Lock()
	defer db.mu.Unlock()

	db.ipv4CIDRs = make(map[string]string)
	db.ipv6CIDRs = make(map[string]string)

	header := make([]byte, 12)
	if _, err := io.ReadFull(file, header); err != nil {
		if err == io.EOF {
			return db.loadSimpleFormat(file)
		}
		return fmt.Errorf("failed to read header: %w", err)
	}

	magic := string(header[:4])
	if magic != "v2rg" {
		return db.loadSimpleFormat(file)
	}
	_ = binary.BigEndian.Uint32(header[4:8])

	count := binary.BigEndian.Uint32(header[8:12])

	loadedCount := 0
	for i := uint32(0); i < count; i++ {
		cidrLenBytes := make([]byte, 1)
		if _, err := io.ReadFull(file, cidrLenBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		cidrLen := int(cidrLenBytes[0])

		var ipBytes []byte
		if cidrLen <= 32 {
			ipBytes = make([]byte, 4)
		} else if cidrLen <= 128 {
			ipBytes = make([]byte, 16)
		} else {
			continue
		}

		if _, err := io.ReadFull(file, ipBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		ccLenBytes := make([]byte, 1)
		if _, err := io.ReadFull(file, ccLenBytes); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		ccLen := int(ccLenBytes[0])

		if ccLen == 0 || ccLen > 10 {
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
		ip := net.IP(ipBytes)

		cidr := fmt.Sprintf("%s/%d", ip.String(), cidrLen)

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		if cidrLen <= 32 {
			db.ipv4CIDRs[network.String()] = countryCode
		} else {
			db.ipv6CIDRs[network.String()] = countryCode
		}
		loadedCount++
	}
	if loadedCount == 0 {
		return db.loadSimpleFormat(file)
	}

	return nil
}

func (db *GeoIPDatabase) loadSimpleFormat(file *os.File) error {
	file.Seek(0, 0) 
	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	lines := splitLines(string(data))
	loadedCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		parts := splitByCommaOrSpace(line)
		if len(parts) < 2 {
			continue
		}

		cidr := strings.TrimSpace(parts[0])
		countryCode := strings.TrimSpace(parts[1])

		if len(countryCode) == 0 || len(countryCode) > 10 {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		normalizedCIDR := network.String()

		if network.IP.To4() != nil {
			db.ipv4CIDRs[normalizedCIDR] = countryCode
		} else {
			db.ipv6CIDRs[normalizedCIDR] = countryCode
		}
		loadedCount++
	}

	if loadedCount == 0 {
		return fmt.Errorf("no valid entries found in file")
	}

	return nil
}

func (db *GeoIPDatabase) LookupCountry(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	if ipv4 := ip.To4(); ipv4 != nil {
		bestMatch := ""
		bestPrefixLen := -1

		for cidr, countryCode := range db.ipv4CIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			if network.Contains(ip) {
				ones, _ := network.Mask.Size()
				if ones > bestPrefixLen {
					bestPrefixLen = ones
					bestMatch = countryCode
				}
			}
		}

		if bestMatch != "" {
			return bestMatch, true
		}
	} else {
		bestMatch := ""
		bestPrefixLen := -1

		for cidr, countryCode := range db.ipv6CIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			if network.Contains(ip) {
				ones, _ := network.Mask.Size()
				if ones > bestPrefixLen {
					bestPrefixLen = ones
					bestMatch = countryCode
				}
			}
		}

		if bestMatch != "" {
			return bestMatch, true
		}
	}

	return "", false
}

func (db *GeoIPDatabase) AddCIDR(cidr, countryCode string) error {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	if ip.To4() != nil {
		db.ipv4CIDRs[cidr] = countryCode
	} else {
		db.ipv6CIDRs[cidr] = countryCode
	}

	return nil
}

func (db *GeoIPDatabase) GetCountryCIDRs(countryCode string) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []string
	for cidr, cc := range db.ipv4CIDRs {
		if cc == countryCode {
			result = append(result, cidr)
		}
	}
	for cidr, cc := range db.ipv6CIDRs {
		if cc == countryCode {
			result = append(result, cidr)
		}
	}

	return result
}

func (db *GeoIPDatabase) IsInCountry(ip net.IP, countryCode string) bool {
	cc, found := db.LookupCountry(ip)
	if !found {
		return false
	}
	return cc == countryCode
}

func (db *GeoIPDatabase) GetAllCountries() []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	countriesSet := make(map[string]bool)
	for _, country := range db.ipv4CIDRs {
		countriesSet[country] = true
	}
	for _, country := range db.ipv6CIDRs {
		countriesSet[country] = true
	}

	countries := make([]string, 0, len(countriesSet))
	for country := range countriesSet {
		countries = append(countries, country)
	}
	return countries
}

func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if len(line) > 0 {
			result = append(result, line)
		}
	}
	return result
}

func splitByCommaOrSpace(s string) []string {
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		var result []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if len(p) > 0 {
				result = append(result, p)
			}
		}
		if len(result) >= 2 {
			return result
		}
	}

	parts := strings.Fields(s)
	return parts
}
func DownloadGeoIP(url string, outputPath string) error {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download geoip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download geoip: status %d", resp.StatusCode)
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
