package evasion

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"strings"
)

func (m *Marionette) generateTLSExtensions() []byte {
	extensions := make([]byte, 0, 128)
	m.Mutex.RLock()
	activeProfile := m.Active
	m.Mutex.RUnlock()

	hostname := "example.com"
	switch activeProfile {
	case "vk":
		hostname = "vk.com"
	case "yandex":
		hostname = "yandex.ru"
	case "mailru":
		hostname = "mail.ru"
	case "rutube":
		hostname = "rutube.ru"
	case "ozon":
		hostname = "ozon.ru"
	}

	sniHost := hostname
	sniNameLen := len(sniHost)
	sniListLen := 3 + sniNameLen
	extLen := 2 + sniListLen

	extensions = append(extensions,
		0x00, 0x00,
		byte(extLen>>8), byte(extLen),
		byte(sniListLen>>8), byte(sniListLen),
		0x00,
		byte(sniNameLen>>8), byte(sniNameLen),
	)
	extensions = append(extensions, []byte(sniHost)...)

	var alpnH2 = [3]byte{0x02, 'h', '2'}
	var alpnH11 = [9]byte{0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	alpnListLen := len(alpnH2) + len(alpnH11)
	alpnExtLen := 2 + alpnListLen

	extensions = append(extensions,
		0x00, 0x10,
		byte(alpnExtLen>>8), byte(alpnExtLen),
		byte(alpnListLen>>8), byte(alpnListLen),
	)
	extensions = append(extensions, alpnH2[:]...)
	extensions = append(extensions, alpnH11[:]...)

	return extensions
}

type TLSServiceProfile struct {
	Name                      string
	TLSVersion                string
	CipherSuites              []string
	Extensions                []string
	EllipticCurves            []string
	EllipticCurvePointFormats []string
}

func (m *Marionette) getCurrentServiceProfile() *TLSServiceProfile {
	activeProfile := m.GetActiveProfile()
	switch activeProfile {
	case "vk":
		return &TLSServiceProfile{
			Name: "VKontakte", TLSVersion: "771",
			CipherSuites:              []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53"},
			Extensions:                []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513"},
			EllipticCurves:            []string{"29", "23", "24"},
			EllipticCurvePointFormats: []string{"0"},
		}
	case "yandex":
		return &TLSServiceProfile{
			Name: "Yandex", TLSVersion: "771",
			CipherSuites:              []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53", "10", "19"},
			Extensions:                []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513", "21", "22"},
			EllipticCurves:            []string{"29", "23", "24", "25"},
			EllipticCurvePointFormats: []string{"0", "1"},
		}
	case "mailru":
		return &TLSServiceProfile{
			Name: "Mail.ru", TLSVersion: "771",
			CipherSuites:              []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53", "5", "4"},
			Extensions:                []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513", "28", "29"},
			EllipticCurves:            []string{"29", "23", "24", "30"},
			EllipticCurvePointFormats: []string{"0", "2"},
		}
	case "rutube":
		return &TLSServiceProfile{
			Name: "Rutube", TLSVersion: "771",
			CipherSuites:              []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53", "9", "8"},
			Extensions:                []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513", "41", "42"},
			EllipticCurves:            []string{"29", "23", "24", "26"},
			EllipticCurvePointFormats: []string{"0", "1", "2"},
		}
	case "ozon":
		return &TLSServiceProfile{
			Name: "Ozon", TLSVersion: "771",
			CipherSuites:              []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53", "6", "7"},
			Extensions:                []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513", "31", "32"},
			EllipticCurves:            []string{"29", "23", "24", "27"},
			EllipticCurvePointFormats: []string{"0", "1"},
		}
	default:
		return &TLSServiceProfile{
			Name: "Generic", TLSVersion: "771",
			CipherSuites:              []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392", "49171", "49172", "156", "157", "47", "53"},
			Extensions:                []string{"0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43", "27", "17513"},
			EllipticCurves:            []string{"29", "23", "24"},
			EllipticCurvePointFormats: []string{"0"},
		}
	}
}

func (m *Marionette) applyJA3Evasion(_ []byte) []byte {
	clientHello := m.generateTLSClientHello()
	ja3Hash := m.calculateJA3Hash(clientHello)
	ja3Obfuscation := make([]byte, 16)
	copy(ja3Obfuscation, ja3Hash)
	extensions := m.generateTLSExtensions()
	ja3Obfuscation = append(ja3Obfuscation, extensions...)
	return ja3Obfuscation
}

func (m *Marionette) generateTLSClientHello() []byte {
	clientHello := make([]byte, 0, 512)
	clientHello = append(clientHello, 0x03, 0x03)
	random := make([]byte, 32)
	rand.Read(random)
	clientHello = append(clientHello, random...)

	sessionIDLen := cryptoRandInt(33)
	sessionID := make([]byte, sessionIDLen)
	rand.Read(sessionID)
	clientHello = append(clientHello, byte(sessionIDLen))
	clientHello = append(clientHello, sessionID...)

	allCiphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	numCiphers := 3 + cryptoRandInt(len(allCiphers)-3)
	used := make(map[int]bool)
	var ciphers []uint16
	for len(ciphers) < numCiphers {
		idx := cryptoRandInt(len(allCiphers))
		if !used[idx] {
			used[idx] = true
			ciphers = append(ciphers, allCiphers[idx])
		}
	}
	clientHello = append(clientHello, byte(len(ciphers)*2>>8), byte(len(ciphers)*2&0xFF))
	for _, suite := range ciphers {
		clientHello = append(clientHello, byte(suite>>8), byte(suite&0xFF))
	}
	clientHello = append(clientHello, 0x01, 0x00)
	return clientHello
}

func (m *Marionette) calculateJA3Hash(_ []byte) []byte {
	profile := m.getCurrentServiceProfile()
	ja3String := m.buildJA3String(profile)
	hash := m.calculateMD5Hash(ja3String)
	return hash
}

func (m *Marionette) buildJA3String(profile *TLSServiceProfile) string {
	ciphers := strings.Join(profile.CipherSuites, "-")
	extensions := strings.Join(profile.Extensions, "-")
	curves := strings.Join(profile.EllipticCurves, "-")
	pointFormats := strings.Join(profile.EllipticCurvePointFormats, "-")
	return fmt.Sprintf("%s,%s,%s,%s,%s", profile.TLSVersion, ciphers, extensions, curves, pointFormats)
}

func (m *Marionette) calculateMD5Hash(input string) []byte {
	hash := md5.Sum([]byte(input))
	return hash[:]
}

func (m *Marionette) applyJA4Evasion(_ []byte) []byte {
	extensions := m.generateJA4Extensions()
	ja4Hash := m.calculateJA4Hash(extensions)
	ja4Obfuscation := make([]byte, 20)
	copy(ja4Obfuscation, ja4Hash)
	ja4Obfuscation = append(ja4Obfuscation, extensions...)
	return ja4Obfuscation
}

func (m *Marionette) calculateJA4Hash(extensions []byte) []byte {
	hash := md5.Sum(extensions)
	return hash[:]
}

func (m *Marionette) generateJA4Extensions() []byte {
	size := 16 + cryptoRandInt(64)
	buf := make([]byte, size)
	rand.Read(buf)
	return buf
}
