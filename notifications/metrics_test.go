package notifications

import (
	"encoding/json"
	"expvar"
	"net/http"
	"testing"
)

func TestMetricsExpvar(t *testing.T) {
	endpointsVar := expvar.Get("registry").(*expvar.Map).Get("notifications").(*expvar.Map).Get("endpoints")

	var v interface{}
	if err := json.Unmarshal([]byte(endpointsVar.String()), &v); err != nil {
		t.Fatalf("unexpected error unmarshaling endpoints: %v", err)
	}
	if v != nil {
		t.Fatalf("expected nil, got %#v", v)
	}

	NewEndpoint("x", "y", EndpointConfig{})

	if err := json.Unmarshal([]byte(endpointsVar.String()), &v); err != nil {
		t.Fatalf("unexpected error unmarshaling endpoints: %v", err)
	}
	if slice, ok := v.([]interface{}); !ok || len(slice) != 1 {
		t.Logf("expected one-element []interface{}, got %#v", v)
	}
}

func TestSanitizeHeaders(t *testing.T) {
	if got := SanitizeHeaders(nil); got != nil {
		t.Fatalf("expected nil for nil headers, got %v", got)
	}

	headers := http.Header{
		"Authorization":       []string{"Bearer supersecret"},
		"authorization":       []string{"Basic dXNlcjpwYXNz"},
		"Proxy-Authorization": []string{"Basic cHJveHk6cGFzcw=="},
		"proxy-authorization": []string{"Basic cHJveHk6cGFzcw=="},
		"Cookie":              []string{"session=123456"},
		"cookie":              []string{"session=654321"},
		"Set-Cookie":          []string{"auth=token123"},
		"set-cookie":          []string{"auth=token456"},
		"X-Custom-Token":      []string{"mytoken"},
		"X-Api-Key":           []string{"apikey-xyz"},
		"Client-Secret":       []string{"clientsecret"},
		"DB-Password":         []string{"dbpass"},
		"Content-Type":        []string{"application/json"},
		"User-Agent":          []string{"distribution/test"},
		"Accept":              []string{"*/*"},
	}

	sanitized := SanitizeHeaders(headers)

	sensitiveKeys := []string{
		"Authorization",
		"authorization",
		"Proxy-Authorization",
		"proxy-authorization",
		"Cookie",
		"cookie",
		"Set-Cookie",
		"set-cookie",
		"X-Custom-Token",
		"X-Api-Key",
		"Client-Secret",
		"DB-Password",
	}

	for _, k := range sensitiveKeys {
		vals := sanitized[k]
		if len(vals) != 1 || vals[0] != "********" {
			t.Errorf("expected header %q to be masked with '********', got %v", k, vals)
		}
	}

	nonSensitive := map[string][]string{
		"Content-Type": {"application/json"},
		"User-Agent":   {"distribution/test"},
		"Accept":       {"*/*"},
	}

	for k, expected := range nonSensitive {
		vals := sanitized[k]
		if len(vals) != len(expected) || vals[0] != expected[0] {
			t.Errorf("expected header %q to remain %v, got %v", k, expected, vals)
		}
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "http://user:password@example.com/webhook",
			expected: "http://user:xxxxx@example.com/webhook",
		},
		{
			input:    "https://admin:p%40ssword@example.com:8443/notify?param=1",
			expected: "https://admin:xxxxx@example.com:8443/notify?param=1",
		},
		{
			input:    "http://secret-token@example.com/webhook",
			expected: "http://xxxxx@example.com/webhook",
		},
		{
			input:    "http://example.com/webhook?key=value",
			expected: "http://example.com/webhook?key=value",
		},
		{
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		got := SanitizeURL(tc.input)
		if got != tc.expected {
			t.Errorf("SanitizeURL(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestMetricsExpvarSanitization(t *testing.T) {
	ep := NewEndpoint("test-masked-ep", "http://myuser:mypassword@example.com/notify", EndpointConfig{
		Headers: http.Header{
			"Authorization":       []string{"Bearer secret-jwt"},
			"Proxy-Authorization": []string{"Basic proxy-pass"},
			"X-Api-Key":           []string{"private-key"},
			"Content-Type":        []string{"application/json"},
		},
	})
	if ep == nil {
		t.Fatal("failed to create endpoint")
	}

	endpointsVar := expvar.Get("registry").(*expvar.Map).Get("notifications").(*expvar.Map).Get("endpoints")

	var records []struct {
		Name    string      `json:"name"`
		URL     string      `json:"url"`
		Headers http.Header `json:"Headers"`
	}

	if err := json.Unmarshal([]byte(endpointsVar.String()), &records); err != nil {
		t.Fatalf("unexpected error unmarshaling endpoints expvar: %v", err)
	}

	var found bool
	for _, rec := range records {
		if rec.Name == "test-masked-ep" {
			found = true
			if rec.URL != "http://myuser:xxxxx@example.com/notify" {
				t.Errorf("expected URL to be sanitized in expvar, got %q", rec.URL)
			}
			if rec.Headers.Get("Authorization") != "********" {
				t.Errorf("expected Authorization header to be masked, got %q", rec.Headers.Get("Authorization"))
			}
			if rec.Headers.Get("Proxy-Authorization") != "********" {
				t.Errorf("expected Proxy-Authorization header to be masked, got %q", rec.Headers.Get("Proxy-Authorization"))
			}
			if rec.Headers.Get("X-Api-Key") != "********" {
				t.Errorf("expected X-Api-Key header to be masked, got %q", rec.Headers.Get("X-Api-Key"))
			}
			if rec.Headers.Get("Content-Type") != "application/json" {
				t.Errorf("expected Content-Type to remain intact, got %q", rec.Headers.Get("Content-Type"))
			}
		}
	}

	if !found {
		t.Fatal("expected test-masked-ep in expvar records")
	}
}
