package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

const TestedGOGVersion = "v0.38.2"
const RequiredGOGBuild = "03d192ff-mailgate.1"

type GOG struct {
	config   Config
	password string
	slots    chan struct{}
}

func NewGOG(c Config, s Secrets) *GOG {
	return &GOG{config: c, password: s.GOGPassword, slots: make(chan struct{}, c.MaxConcurrentGOG)}
}

type cappedBuffer struct {
	mu       sync.Mutex
	data     bytes.Buffer
	maximum  int
	cancel   context.CancelFunc
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > b.maximum-b.data.Len() {
		b.exceeded = true
		b.cancel()
		return 0, errors.New("output limit reached")
	}
	return b.data.Write(p)
}

// run never invokes a shell or inherits the caller's environment. The account,
// credential store and exact command allowlist cannot be supplied by API clients.
func (g *GOG) run(ctx context.Context, operation string, args []string, stdin string) ([]byte, error) {
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	case <-ctx.Done():
		return nil, ErrBackend
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(g.config.GOGTimeoutSeconds)*time.Second)
	defer cancel()
	base := []string{"--json", "--no-input", "--color=never", "--account=" + g.config.GOGAccount, "--client=" + g.config.GOGClient, "--home=" + g.config.GOGHome, "--enable-commands-exact=" + operation}
	if operation == "gmail.get" || operation == "gmail.messages.search" {
		base = append(base, "--readonly", "--gmail-no-send")
	}
	if operation == "version" {
		base = nil
	}
	cmd := exec.CommandContext(ctx, g.config.GOGPath, append(base, args...)...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + g.config.GOGHome, "LANG=C.UTF-8", "TZ=UTC", "GOG_KEYRING_BACKEND=file", "GOG_KEYRING_PASSWORD=" + g.password}
	cmd.Stdin = strings.NewReader(stdin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 500 * time.Millisecond
	out := &cappedBuffer{maximum: g.config.MaxGOGOutputBytes, cancel: cancel}
	stderr := &cappedBuffer{maximum: 16384, cancel: cancel}
	cmd.Stdout, cmd.Stderr = out, stderr
	err := cmd.Run()
	if err != nil {
		// The CLI has no typed 404 exit code. Only inspect this known Google API
		// error signature; never expose stderr (it can contain mail or credentials).
		if operation == "gmail.get" && strings.Contains(stderr.data.String(), "googleapi: Error 404:") {
			return nil, ErrNotFound
		}
		return nil, ErrBackend
	}
	if out.exceeded || stderr.exceeded {
		return nil, ErrBackend
	}
	return out.data.Bytes(), nil
}

func (g *GOG) Verify(ctx context.Context) error {
	out, err := g.run(ctx, "version", []string{"--version"}, "")
	if err != nil {
		return err
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 || fields[0] != TestedGOGVersion || fields[1] != "("+RequiredGOGBuild+")" {
		return errors.New("GOG build mismatch: run scripts/build-gog.sh to build " + TestedGOGVersion + " with the single-attempt send patch")
	}
	return nil
}

func (g *GOG) Search(ctx context.Context, query, page string, limit int) (SearchPage, error) {
	if limit < 1 || limit > 50 || len(query) > 2048 || len(page) > 4096 {
		return SearchPage{}, ErrBackend
	}
	args := []string{"gmail", "messages", "search", "--max=" + strconv.Itoa(limit)}
	if page != "" {
		args = append(args, "--page="+page)
	}
	args = append(args, "--", query)
	out, err := g.run(ctx, "gmail.messages.search", args, "")
	if err != nil {
		return SearchPage{}, err
	}
	var envelope struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
		NextPage string `json:"nextPageToken"`
	}
	if json.Unmarshal(out, &envelope) != nil || len(envelope.Messages) > limit || len(envelope.NextPage) > 4096 {
		return SearchPage{}, ErrBackend
	}
	// Require the expected envelope, including the messages key, rather than
	// silently interpreting an incompatible CLI schema as an empty mailbox.
	var keys map[string]json.RawMessage
	if json.Unmarshal(out, &keys) != nil || keys["messages"] == nil {
		return SearchPage{}, ErrBackend
	}
	result := SearchPage{NextPage: envelope.NextPage}
	for _, m := range envelope.Messages {
		if !messageIDPattern.MatchString(m.ID) {
			return SearchPage{}, ErrBackend
		}
		result.IDs = append(result.IDs, m.ID)
	}
	return result, nil
}

func (g *GOG) Read(ctx context.Context, id string) (Message, error) {
	if !messageIDPattern.MatchString(id) {
		return Message{}, ErrNotFound
	}
	out, err := g.run(ctx, "gmail.get", []string{"gmail", "get", "--format=full", "--", id}, "")
	if err != nil {
		return Message{}, err
	}
	m, err := ParseGOGMessage(out)
	if err != nil {
		return Message{}, ErrBackend
	}
	if m.ID != id {
		return Message{}, ErrBackend
	}
	return m, nil
}

func (g *GOG) Send(ctx context.Context, m Outgoing) (SentMessage, error) {
	args := []string{"gmail", "send", "--to=" + strings.Join(m.To, ","), "--subject=" + m.Subject, "--body-file=-"}
	if len(m.CC) > 0 {
		args = append(args, "--cc="+strings.Join(m.CC, ","))
	}
	if len(m.BCC) > 0 {
		args = append(args, "--bcc="+strings.Join(m.BCC, ","))
	}
	out, err := g.run(ctx, "gmail.send", args, m.Body)
	if err != nil {
		return SentMessage{}, err
	}
	var envelope struct {
		MessageID string `json:"messageId"`
		ThreadID  string `json:"threadId"`
	}
	if json.Unmarshal(out, &envelope) != nil || !messageIDPattern.MatchString(envelope.MessageID) {
		return SentMessage{}, ErrBackend
	}
	return SentMessage{ID: envelope.MessageID, ThreadID: envelope.ThreadID}, nil
}

type gmailHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type gmailPart struct {
	MimeType string        `json:"mimeType"`
	Filename string        `json:"filename"`
	Headers  []gmailHeader `json:"headers"`
	Body     struct {
		Data         string `json:"data"`
		AttachmentID string `json:"attachmentId"`
		Size         int    `json:"size"`
	} `json:"body"`
	Parts []gmailPart `json:"parts"`
}

// ParseGOGMessage inspects every MIME alternative, including quoted content and
// HTML that is not selected for display. Unscannable attachments are withheld.
func ParseGOGMessage(data []byte) (Message, error) {
	var envelope struct {
		Message struct {
			ID       string     `json:"id"`
			ThreadID string     `json:"threadId"`
			Labels   []string   `json:"labelIds"`
			Snippet  string     `json:"snippet"`
			Payload  *gmailPart `json:"payload"`
		} `json:"message"`
	}
	if len(data) > 8<<20 {
		return Message{}, ErrBackend
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Message{}, err
	}
	g := envelope.Message
	if !messageIDPattern.MatchString(g.ID) || g.Payload == nil || len(g.Payload.Headers) == 0 {
		return Message{}, ErrBackend
	}
	m := Message{ID: g.ID, ThreadID: g.ThreadID, LabelIDs: g.Labels, Untrusted: true}
	decoder := &mime.WordDecoder{CharsetReader: charset.NewReaderLabel}
	for _, h := range g.Payload.Headers {
		value, err := decoder.DecodeHeader(h.Value)
		if err != nil {
			m.Uninspectable = true
			continue
		}
		switch strings.ToLower(h.Name) {
		case "from":
			m.From = value
		case "to":
			m.To = value
		case "cc":
			m.CC = value
		case "subject":
			m.Subject = value
		case "date":
			m.Date = value
		}
	}
	var scan, plain, htmlBodies strings.Builder
	scan.WriteString(g.Snippet)
	nodes := 0
	var visit func(gmailPart, int)
	visit = func(p gmailPart, depth int) {
		nodes++
		if depth > 32 || nodes > 256 || scan.Len() > 1<<20 {
			m.Uninspectable = true
			return
		}
		if p.Filename != "" || p.Body.AttachmentID != "" {
			m.Uninspectable = true
			return
		}
		if p.Body.Data != "" {
			body, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(p.Body.Data, "="))
			if err != nil {
				m.Uninspectable = true
				return
			}
			if len(body) > 1<<20 {
				m.Uninspectable = true
				return
			}
			kind := strings.ToLower(p.MimeType)
			if kind != "text/plain" && kind != "text/html" {
				m.Uninspectable = true
				return
			}
			for _, h := range p.Headers {
				if strings.EqualFold(h.Name, "Content-Type") {
					_, params, err := mime.ParseMediaType(h.Value)
					if err != nil {
						m.Uninspectable = true
						return
					}
					if cs := params["charset"]; cs != "" {
						reader, err := charset.NewReaderLabel(cs, bytes.NewReader(body))
						if err != nil {
							m.Uninspectable = true
							return
						}
						body, err = io.ReadAll(io.LimitReader(reader, (1<<20)+1))
						if err != nil || len(body) > 1<<20 {
							m.Uninspectable = true
							return
						}
					}
				}
			}
			if !utf8.Valid(body) {
				m.Uninspectable = true
				return
			}
			scan.WriteByte('\n')
			scan.Write(body)
			if kind == "text/plain" {
				plain.Write(body)
				plain.WriteByte('\n')
			} else {
				text, err := htmlText(string(body))
				if err != nil {
					m.Uninspectable = true
					return
				}
				scan.WriteByte('\n')
				scan.WriteString(text)
				htmlBodies.WriteString(text)
				htmlBodies.WriteByte('\n')
			}
		} else if p.Body.Size > 0 {
			m.Uninspectable = true
			return
		}
		for _, child := range p.Parts {
			visit(child, depth+1)
		}
	}
	visit(*g.Payload, 0)
	m.Body = strings.TrimSpace(plain.String())
	if m.Body == "" {
		m.Body = strings.TrimSpace(htmlBodies.String())
	}
	m.ScanText = scan.String()
	if len(m.Body) > 256<<10 || len(m.ScanText) > 2<<20 {
		m.Uninspectable = true
		m.Body = ""
		m.ScanText = ""
	}
	return m, nil
}

func htmlText(input string) (string, error) {
	z := html.NewTokenizer(strings.NewReader(input))
	z.SetMaxBuf(1 << 20)
	var b strings.Builder
	ignore := 0
	for {
		switch z.Next() {
		case html.ErrorToken:
			if z.Err() != io.EOF {
				return "", z.Err()
			}
			return b.String(), nil
		case html.TextToken:
			if ignore == 0 {
				b.Write(z.Text())
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if tag == "script" || tag == "style" {
				ignore++
			}
			if tag == "br" || tag == "p" || tag == "div" || tag == "li" {
				b.WriteByte('\n')
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if (tag == "script" || tag == "style") && ignore > 0 {
				ignore--
			}
			if tag == "p" || tag == "div" || tag == "li" {
				b.WriteByte('\n')
			}
		}
	}
}
