//go:build unit

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsClandesAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		extra  map[string]any
		expect bool
	}{
		{"nil extra", nil, false},
		{"empty extra", map[string]any{}, false},
		{"clandes false", map[string]any{"clandes": false}, false},
		{"clandes true", map[string]any{"clandes": true}, true},
		{"clandes non-bool", map[string]any{"clandes": "yes"}, false},
		{"clandes with other keys", map[string]any{"clandes": true, "other": 42}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc := &Account{Extra: tt.extra}
			require.Equal(t, tt.expect, IsClandesAccount(acc))
		})
	}
}

func TestBuildProxyURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		proxy  *Proxy
		expect string
	}{
		{"nil proxy", nil, ""},
		{
			"http no auth",
			&Proxy{Protocol: "http", Host: "proxy.example.com", Port: 8080},
			"http://proxy.example.com:8080",
		},
		{
			"https with auth",
			&Proxy{Protocol: "https", Host: "proxy.example.com", Port: 443, Username: "user", Password: "pass"},
			"https://user:pass@proxy.example.com:443",
		},
		{
			"socks5 no auth",
			&Proxy{Protocol: "socks5", Host: "10.0.0.1", Port: 1080},
			"socks5://10.0.0.1:1080",
		},
		{
			"empty protocol defaults to http",
			&Proxy{Protocol: "", Host: "127.0.0.1", Port: 3128},
			"http://127.0.0.1:3128",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expect, BuildProxyURL(tt.proxy))
		})
	}
}

func TestMapAccountTypeToCapnp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		platform string
		accType  string
		isKnown  bool
	}{
		{"anthropic oauth", PlatformAnthropic, AccountTypeOAuth, true},
		{"anthropic setup-token", PlatformAnthropic, AccountTypeSetupToken, true},
		{"anthropic apikey", PlatformAnthropic, AccountTypeAPIKey, true},
		{"openai oauth", "openai", AccountTypeOAuth, false},
		{"anthropic unknown type", PlatformAnthropic, "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc := &Account{Platform: tt.platform, Type: tt.accType}
			result := mapAccountTypeToCapnp(acc)
			if tt.isKnown {
				require.NotEqual(t, result.String(), "unknown")
			} else {
				require.Equal(t, result.String(), "unknown")
			}
		})
	}
}
