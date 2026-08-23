package ipdetect

import (
	"net"
	"testing"
)

func TestPrivateRangesDecideWhetherToAskOutside(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.15.0.1", false},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"192.169.1.1", false},
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"100.63.255.255", false},
		{"100.128.0.1", false},
		{"1.1.1.1", false},
		{"2.26.27.166", false},
		{"198.51.100.10", false},
	}

	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test address %q", c.ip)
		}
		if got := isPrivateIP(ip); got != c.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", c.ip, got, c.private)
		}
	}
}
