package commands

import (
	"strings"
	"testing"
)

func TestValidateHostnameFlagRejects(t *testing.T) {
	cases := []struct {
		value string
		want  string
	}{
		{"https://society.com", `use "society.com"`},
		{"http://society.com/", `use "society.com"`},
		{"society.com/path", "without a path"},
		{"society.com?a=1", "without a path"},
		{"society.com:443", "must not carry a port"},
		{"8.8.8.8", "not an IP address"},
		{"2001:db8::1", "must not carry a port"},
		{"socie ty.com", "not a valid hostname"},
		{"-bad.com", "not a valid hostname"},
		{"bad-.com", "not a valid hostname"},
		{"society..com", "not a valid hostname"},
		{strings.Repeat("a.", 130) + "com", "may not exceed 253"},
	}

	for _, tc := range cases {
		err := validateHostnameFlag("-sni", tc.value)
		if err == nil {
			t.Errorf("%q: accepted", tc.value)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: error %q does not mention %q", tc.value, err, tc.want)
		}
	}
}

func TestValidateHostnameFlagAccepts(t *testing.T) {
	for _, value := range []string{"", "society.com", "SOCIETY.com", "society.com.", "a.b.c.example.org", "xn--80ak6aa92e.com", "www2.example.com"} {
		if err := validateHostnameFlag("-sni", value); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
}
