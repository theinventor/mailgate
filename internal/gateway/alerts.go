package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Notifier struct {
	secrets Secrets
	client  *http.Client
	logger  *slog.Logger
}

func NewNotifier(s Secrets, logger *slog.Logger) *Notifier {
	if logger == nil {
		logger = slog.Default()
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.MaxConnsPerHost = 2
	transport.DisableCompression = true
	return &Notifier{secrets: s, logger: logger, client: &http.Client{Timeout: 10 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (n *Notifier) Channels() []string {
	channels := []string{}
	if n.secrets.PushoverToken != "" && n.secrets.PushoverUser != "" {
		channels = append(channels, "pushover")
	}
	if n.secrets.BRRRKey != "" {
		channels = append(channels, "brrr")
	}
	return channels
}

// Deliver returns a fixed diagnostic code, never a network error containing a
// secret URL, request body, response body, or authentication header.
func (n *Notifier) Deliver(ctx context.Context, job AlertJob) string {
	var req *http.Request
	var err error
	switch job.Channel {
	case "pushover":
		form := url.Values{"token": {n.secrets.PushoverToken}, "user": {n.secrets.PushoverUser}, "title": {"Mailgate security alert"}, "message": {job.Message}, "priority": {"1"}, "sound": {"pushover"}}
		req, err = http.NewRequestWithContext(ctx, "POST", "https://api.pushover.net/1/messages.json", strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	case "brrr":
		body, _ := json.Marshal(map[string]string{"title": "Mailgate security alert", "message": job.Message, "interruption_level": "time-sensitive", "sound": "system", "thread_id": "mailgate-security"})
		req, err = http.NewRequestWithContext(ctx, "POST", "https://api.brrr.now/v1/send", bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+n.secrets.BRRRKey)
		}
	default:
		return "unknown_channel"
	}
	if err != nil {
		return "invalid_request"
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return "delivery_failed"
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Sprintf("http_%d", resp.StatusCode)
	}
	if job.Channel == "pushover" {
		var result struct {
			Status int `json:"status"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result) != nil || result.Status != 1 {
			return "provider_rejected"
		}
	}
	return ""
}

func (n *Notifier) Run(ctx context.Context, store *Store) {
	var wg sync.WaitGroup
	for _, channel := range n.Channels() {
		wg.Go(func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				jobs, err := store.DueAlerts(ctx, channel, time.Now().Unix())
				if err != nil && ctx.Err() == nil {
					n.logger.Error("cannot read alert queue", "channel", channel)
				}
				for _, job := range jobs {
					if ctx.Err() != nil {
						return
					}
					failure := n.Deliver(ctx, job)
					persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					err := store.FinishAlert(persistCtx, job, failure)
					cancel()
					if err != nil {
						n.logger.Error("cannot persist alert delivery", "job_id", job.ID)
					} else if failure != "" {
						n.logger.Warn("alert delivery will retry", "job_id", job.ID, "channel", channel, "failure", failure)
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		})
	}
	wg.Wait()
}
