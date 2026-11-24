// Package slackwebhook delivers notifications to a Slack Incoming Webhook as
// Block Kit messages. The webhook URL is a secret: it is resolved through
// plugin.Deps.Secrets on every delivery and never appears in logs or errors.
package slackwebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/notify"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
)

// Name is the registry name of this notifier.
const Name = "slack-webhook"

const defaultMaxFindings = 10

func init() { notify.Registry.Register(Name, New) }

// Config is the plugin's config block.
type Config struct {
	WebhookEnv   string `mapstructure:"webhook_env"`   // env var holding the webhook URL
	WebhookFile  string `mapstructure:"webhook_file"`  // file holding the webhook URL
	WebhookRef   string `mapstructure:"webhook_ref"`   // id in the encrypted secret store
	ChannelLabel string `mapstructure:"channel_label"` // display only; webhooks are bound to one channel
	UIBaseURL    string `mapstructure:"ui_base_url"`   // optional web UI, e.g. https://heimdall.internal
	MaxFindings  int    `mapstructure:"max_findings"`  // findings listed per message; default 10
}

// Validate implements plugin.Validator.
func (c *Config) Validate() error {
	if c.ref().IsZero() {
		return errors.New("one of webhook_env, webhook_file or webhook_ref is required")
	}
	if c.MaxFindings < 0 {
		return errors.New("max_findings must not be negative")
	}
	if c.UIBaseURL != "" {
		u, err := url.Parse(c.UIBaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("ui_base_url %q must be an absolute http(s) URL", c.UIBaseURL)
		}
	}
	return nil
}

func (c *Config) ref() secret.Ref {
	return secret.Ref{Env: c.WebhookEnv, File: c.WebhookFile, ID: c.WebhookRef}
}

// Notifier implements notify.Notifier.
type Notifier struct {
	cfg     Config
	http    *httpx.Client
	secrets secret.Resolver
	log     *slog.Logger
}

// New builds the notifier from its config block.
func New(cfg plugin.Config, deps plugin.Deps) (notify.Notifier, error) {
	var c Config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if c.MaxFindings == 0 {
		c.MaxFindings = defaultMaxFindings
	}
	c.UIBaseURL = strings.TrimRight(c.UIBaseURL, "/")
	if deps.HTTP == nil {
		return nil, fmt.Errorf("%s: plugin.Deps.HTTP is required", Name)
	}
	n := &Notifier{cfg: c, http: deps.HTTP, secrets: deps.Secrets, log: deps.Logger}
	if n.secrets == nil {
		n.secrets = secret.EnvFile{}
	}
	if n.log == nil {
		n.log = slog.New(slog.DiscardHandler)
	}
	return n, nil
}

// Name implements notify.Notifier.
func (n *Notifier) Name() string { return Name }

// Notify renders ev as Block Kit and posts it to the webhook.
func (n *Notifier) Notify(ctx context.Context, ev model.NotificationEvent) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", Name, err)
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false) // keep Slack's <url|label> links readable
	if err := enc.Encode(render(ev, n.cfg)); err != nil {
		return fmt.Errorf("%s: encode message: %w", Name, err)
	}
	hook, err := n.secrets.Resolve(ctx, n.cfg.ref())
	if err != nil {
		// Resolver errors name the env var / file / id, never the value.
		return fmt.Errorf("%s: resolve webhook URL: %w", Name, err)
	}
	if u, perr := url.Parse(hook); perr != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%s: webhook URL is not an absolute http(s) URL", Name)
	}
	if err := n.post(ctx, hook, body.Bytes()); err != nil {
		return err
	}
	n.log.Debug("slack notification delivered", "event", ev.Type, "channel", n.cfg.ChannelLabel)
	return nil
}

func (n *Notifier) post(ctx context.Context, hook string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: build request: %s", Name, redact(err.Error(), hook))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.http.Do(req)
	if err != nil {
		return deliveryError(ctx, err, hook)
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: webhook returned HTTP %d: %s", Name, resp.StatusCode,
			redact(strings.TrimSpace(string(snippet)), hook))
	}
	return nil
}

// deliveryError hides the webhook URL, which net/http and httpx put in their
// errors. Only context and rate-limit causes stay matchable with errors.Is; the
// original error is not wrapped because its text contains the URL.
func deliveryError(ctx context.Context, err error, hook string) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("%s: deliver: %w", Name, cerr)
	}
	if errors.Is(err, httpx.ErrRateLimited) {
		return fmt.Errorf("%s: deliver: %w", Name, httpx.ErrRateLimited)
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		err = uerr.Err
	}
	return fmt.Errorf("%s: deliver: %s", Name, redact(err.Error(), hook))
}

// redact removes every form of the webhook URL (and its secret path) from s.
func redact(s, hook string) string {
	if hook == "" {
		return s
	}
	const mask = "[redacted webhook]"
	s = strings.ReplaceAll(s, hook, mask)
	if u, err := url.Parse(hook); err == nil {
		for _, v := range []string{u.Redacted(), u.String(), u.EscapedPath(), u.Path} {
			if len(v) > 1 {
				s = strings.ReplaceAll(s, v, mask)
			}
		}
	}
	return s
}
