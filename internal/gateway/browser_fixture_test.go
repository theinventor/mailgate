package gateway

import (
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
	a, _, _ := testAPI(t)
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
