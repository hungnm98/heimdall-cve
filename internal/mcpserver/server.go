// Package mcpserver exposes Heimdall to AI agents over the Model Context
// Protocol (official Go SDK): read tools over scan results, scan triggers,
// agent intelligence writes (advisories, analyses), team notifications,
// two resources and the routines in prompts/ as MCP prompts.
//
// It is an entry point like internal/api: it only calls internal/service and
// never reaches adapters. Write tools are always listed; when the matching
// config flag is off they answer with an error naming the flag, so an agent
// can explain what to enable instead of silently missing a capability.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/prompts"
)

// Auditor records every tool call (store.Catalog implements it).
type Auditor interface {
	AppendAudit(ctx context.Context, e *model.AuditEntry) error
}

// Options configures the server.
type Options struct {
	// AllowScan enables scan_target and scan_repo (mcp.allow_scan). Agent
	// writes and notify are enforced by the services (mcp.allow_agent_writes,
	// mcp.allow_notify in the config they were built with).
	AllowScan bool
	// Config backs the heimdall://config resource (redacted summary); may be nil.
	Config *config.Config
	// Audit receives one entry per tool call; nil disables call auditing.
	Audit   Auditor
	Logger  *slog.Logger
	Version string
	Now     func() time.Time
}

// Server is a Heimdall MCP server.
type Server struct {
	svcs *service.Services
	opts Options
	log  *slog.Logger
	srv  *mcp.Server
}

const instructions = `Heimdall scans the organisation's repositories for vulnerable dependencies and end-of-life runtimes.
Use the read tools to inspect findings, scans and the dependency inventory. Write tools (scan, submit_*, notify_user) may be disabled by configuration; the error says which flag enables them.
Rules: never ask to suppress findings or change configuration; cite https evidence for every claim; research only public libraries (private packages must never leave the organisation); keep notifications concise.`

// New builds the server and registers its tools, resources and prompts.
func New(svcs *service.Services, opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	s := &Server{svcs: svcs, opts: opts, log: opts.Logger}
	s.srv = mcp.NewServer(&mcp.Implementation{Name: "heimdall", Title: "Heimdall", Version: opts.Version},
		&mcp.ServerOptions{Instructions: instructions, Logger: opts.Logger})
	s.addTools()
	s.addResources()
	s.addPrompts()
	return s
}

// RunStdio serves one client over stdin/stdout until ctx is done or the
// client disconnects. Nothing else may write to stdout meanwhile.
func (s *Server) RunStdio(ctx context.Context) error {
	return s.srv.Run(ctx, &mcp.StdioTransport{})
}

// HTTPHandler serves the streamable HTTP transport.
func (s *Server) HTTPHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s.srv }, &mcp.StreamableHTTPOptions{Logger: s.log})
}

// Connect serves one session over t (tests use in-memory transports).
func (s *Server) Connect(ctx context.Context, t mcp.Transport) (*mcp.ServerSession, error) {
	return s.srv.Connect(ctx, t, nil)
}

// actorOf names the caller for the audit log: "mcp:<client name>".
func actorOf(req *mcp.CallToolRequest) service.Actor {
	if req != nil && req.Session != nil {
		if p := req.Session.InitializeParams(); p != nil && p.ClientInfo != nil {
			if name := sanitize(p.ClientInfo.Name, 64); name != "" {
				return service.Actor("mcp:" + name)
			}
		}
	}
	return "mcp"
}

func sanitize(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

// flagFor names the switch enabling a gated tool.
var flagFor = map[string]string{
	"scan_target":     "--allow-scan (config mcp.allow_scan: true)",
	"scan_repo":       "--allow-scan (config mcp.allow_scan: true)",
	"submit_advisory": "--allow-agent-writes (config mcp.allow_agent_writes: true)",
	"submit_analysis": "--allow-agent-writes (config mcp.allow_agent_writes: true)",
	"notify_user":     "--allow-notify (config mcp.allow_notify: true)",
}

var errDisabled = errors.New("disabled")

func disabledError(tool string) error {
	return fmt.Errorf("%s is %w by configuration: an operator must start `heimdall mcp` with %s. Do not retry", tool, errDisabled, flagFor[tool])
}

// toolError turns a service error into text an agent can act on.
func (s *Server) toolError(tool string, err error) error {
	var ve *service.ValidationError
	var up *service.UpstreamError
	switch {
	case errors.Is(err, errDisabled):
		return err
	case errors.As(err, &ve):
		return fmt.Errorf("%s; fix these fields and call again", ve.Error())
	case errors.Is(err, service.ErrForbidden):
		return disabledError(tool)
	case errors.Is(err, service.ErrRateLimited):
		return fmt.Errorf("%v. Do not retry today; put the content in your final summary instead", err)
	case errors.Is(err, service.ErrNotFound):
		return fmt.Errorf("not found: %v", err)
	case errors.Is(err, service.ErrConflict), errors.Is(err, service.ErrUnavailable), errors.As(err, &up):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	}
	s.log.Error("mcp tool failed", "tool", tool, "err", err)
	return errors.New("internal error; see the heimdall log")
}

// audit records a tool call with its arguments. Long strings are cut, so a
// submitted OSV record or message body does not bloat the log; no argument of
// any tool is a secret (auth profiles are referenced by name only).
func (s *Server) audit(ctx context.Context, actor service.Actor, tool string, args any, err error) {
	if s.opts.Audit == nil {
		return
	}
	details := map[string]any{"ok": err == nil}
	if b, merr := json.Marshal(args); merr == nil {
		var m map[string]any
		if json.Unmarshal(b, &m) == nil && len(m) > 0 {
			details["args"] = trimArgs(m)
		}
	}
	if err != nil {
		details["error"] = sanitize(err.Error(), 300)
	}
	e := &model.AuditEntry{At: s.opts.Now().UTC(), Actor: string(actor), Action: "mcp.call", ObjectType: "tool", ObjectID: tool, Details: details}
	if aerr := s.opts.Audit.AppendAudit(context.WithoutCancel(ctx), e); aerr != nil {
		s.log.Error("mcp audit append failed", "tool", tool, "err", aerr)
	}
}

func trimArgs(m map[string]any) map[string]any {
	for k, v := range m {
		switch x := v.(type) {
		case string:
			m[k] = sanitize(x, 200)
		case map[string]any, []any:
			if b, _ := json.Marshal(x); len(b) > 200 {
				m[k] = sanitize(string(b), 200)
			}
		}
	}
	return m
}

// addTool registers a typed tool with auditing and error mapping. The output
// is always a JSON object (structured content + its text form).
func addTool[In any](s *Server, name, desc string, h func(ctx context.Context, actor service.Actor, in In) (any, error)) {
	mcp.AddTool(s.srv, &mcp.Tool{Name: name, Description: desc}, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		actor := actorOf(req)
		out, err := h(ctx, actor, in)
		s.audit(ctx, actor, name, in, err)
		if err != nil {
			return nil, nil, s.toolError(name, err)
		}
		return nil, out, nil
	})
}

func (s *Server) addResources() {
	s.srv.AddResource(&mcp.Resource{
		URI: "heimdall://runs/latest", Name: "latest-run", MIMEType: "application/json",
		Description: "Summary of the latest finished scan run (status, stats, failed repos, source health).",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		page, err := s.svcs.Runs.List(ctx, 0, 1)
		if err != nil {
			return nil, s.toolError("heimdall://runs/latest", err)
		}
		out := map[string]any{"run": nil}
		if len(page.Items) > 0 {
			out["run"] = toRun(page.Items[0])
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return nil, err
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "application/json", Text: string(b)}}}, nil
	})
	s.srv.AddResource(&mcp.Resource{
		URI: "heimdall://config", Name: "config", MIMEType: "text/plain",
		Description: "Redacted configuration summary (no secret values) and what this MCP server allows.",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: s.configSummary()}}}, nil
	})
}

func (s *Server) configSummary() string {
	var b strings.Builder
	if c := s.opts.Config; c != nil {
		b.WriteString(c.Summary())
		fmt.Fprintf(&b, "mcp: allow_scan %v, allow_agent_writes %v, allow_notify %v, notify_daily_limit %d\n",
			s.opts.AllowScan, c.MCP.AllowAgentWrites, c.MCP.AllowNotify, c.MCP.NotifyDailyLimit)
	} else {
		fmt.Fprintf(&b, "no configuration loaded\nmcp: allow_scan %v\n", s.opts.AllowScan)
	}
	fmt.Fprintf(&b, "agent intelligence: %v\n", s.svcs.Intel != nil)
	return b.String()
}

func (s *Server) addPrompts() {
	for _, p := range prompts.All() {
		s.srv.AddPrompt(&mcp.Prompt{Name: p.Name, Title: p.Title, Description: p.Title + " (Heimdall agent routine, prompts/" + p.Name + ".md)"},
			func(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
				return &mcp.GetPromptResult{
					Description: p.Title,
					Messages:    []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: p.Text}}},
				}, nil
			})
	}
}
