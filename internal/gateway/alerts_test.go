package gateway

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestNotificationProviderContractsAndPrivacy(t *testing.T) {
	n := NewNotifier(Secrets{PushoverToken: "push-app-secret", PushoverUser: "push-user-secret", BRRRKey: "brrr-secret"}, nil)
	if len(n.Channels()) != 2 {
		t.Fatal("missing provider")
	}
	n.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.Scheme != "https" || r.URL.RawQuery != "" {
			t.Fatal("unsafe notification URL")
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if r.URL.Host == "api.pushover.net" {
			form, err := url.ParseQuery(string(data))
			if err != nil || form.Get("token") != "push-app-secret" || form.Get("user") != "push-user-secret" {
				t.Fatal("wrong Pushover authentication")
			}
		}
		if r.URL.Host == "api.brrr.now" {
			if r.Header.Get("Authorization") != "Bearer brrr-secret" || strings.Contains(string(data), "brrr-secret") {
				t.Fatal("wrong brrr authentication")
			}
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"status":1}`)), Request: r}, nil
	})
	for _, channel := range n.Channels() {
		if failure := n.Deliver(context.Background(), AlertJob{Channel: channel, Message: "Safe audit reference"}); failure != "" {
			t.Fatal(failure)
		}
	}
	n.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://untrusted.invalid/capture"}}, Body: io.NopCloser(strings.NewReader("provider-secret-response")), Request: r}, nil
	})
	if failure := n.Deliver(context.Background(), AlertJob{Channel: "brrr", Message: "test"}); failure != "http_302" {
		t.Fatalf("redirect or response leakage: %s", failure)
	}
}
