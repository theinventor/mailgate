package gateway

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TestBrowserFixture runs only when invoked by scripts/browser-test.cjs. It
// uses an isolated temporary database, fake Gmail, and an ephemeral TLS port.
func TestBrowserFixture(t *testing.T) {
	path := os.Getenv("MAILGATE_BROWSER_URL_FILE")
	if path == "" {
		t.Skip("browser-test fixture only")
	}
	a, store, _ := testAPI(t)
	if err := store.Record(context.Background(), Event{Action: "request.completed", TokenID: "fixture-token", TokenName: "Alert detail test bot", Route: "unrecognized", Status: 404, Details: map[string]any{"method": "GET", "path": "/v1/labels", "rule": "unknown_endpoint", "query_preview": `<img src=x onerror="window.alertDetailXSS=true">`}}, nil, ""); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(a.AdminHTTPServer().Handler)
	defer server.Close()
	a.config.AdminOrigin = server.URL
	if err := os.WriteFile(path, []byte(server.URL), 0600); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(3 * time.Minute)
	for {
		select {
		case <-deadline:
			t.Fatal("browser test timed out")
		case <-ticker.C:
			if _, err := os.Stat(path + ".done"); err == nil {
				return
			}
		}
	}
}
