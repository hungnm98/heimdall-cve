// Package notify is the port for notification channels (Slack webhook now;
// Slack bot, Teams, email, Jira later). Deciding *what* to send (diff only,
// idempotency) is the core's job; a Notifier only renders and delivers.
package notify

import (
	"context"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
)

// Notifier delivers one event.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, ev model.NotificationEvent) error
}

// Factory builds a Notifier.
type Factory = func(cfg plugin.Config, deps plugin.Deps) (Notifier, error)

// Registry holds notifiers by name ("slack-webhook").
var Registry = registry.New[Factory]("notifier")
