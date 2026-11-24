package model

// EventType names a notification event.
type EventType string

const (
	EventScanSummary      EventType = "scan.summary"
	EventFindingNew       EventType = "finding.new"
	EventFindingSLABreach EventType = "finding.sla_breached"
	EventRuntimeEOLSoon   EventType = "runtime.eol_soon"
	EventAgentMessage     EventType = "agent.message" // sent by an AI agent through MCP
)

// NotificationEvent is what notifiers render and deliver.
type NotificationEvent struct {
	Type     EventType
	Title    string
	Body     string
	Severity Severity
	Run      *ScanRun
	Diff     *Diff
	Findings []Finding
	Links    []string
	Channel  string // optional routing override
}
