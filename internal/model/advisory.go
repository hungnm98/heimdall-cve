package model

import (
	"strings"
	"time"
)

// Severity is normalised across sources.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

// Rank orders severities: CRITICAL=4 … UNKNOWN=0.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// AtLeast reports whether s is as severe as min.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

// ParseSeverity normalises free-form severity labels ("moderate", "High"...).
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH", "IMPORTANT":
		return SeverityHigh
	case "MEDIUM", "MODERATE":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	}
	return SeverityUnknown
}

// SeverityFromCVSS maps a CVSS v3/v4 base score to a severity.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityUnknown
}

// VersionRange follows OSV semantics: affected from Introduced up to (excluding)
// Fixed, or up to (including) LastAffected.
type VersionRange struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// Affected is one package an advisory applies to.
type Affected struct {
	Ecosystem Ecosystem
	Name      string
	Ranges    []VersionRange
	Versions  []string // explicit affected versions, if listed
}

// Advisory is a vulnerability record, OSV-shaped regardless of origin.
type Advisory struct {
	ID         string
	Aliases    []string
	Summary    string
	Details    string
	Severity   Severity
	CVSSVector string
	CVSSScore  float64
	Affected   []Affected
	References []string
	Published  time.Time
	Modified   time.Time
	Withdrawn  *time.Time
	Sources    []string // sources that reported it (union after dedup)
	Verified   bool     // false for unconfirmed agent-submitted advisories
}

// IDs returns ID followed by aliases.
func (a Advisory) IDs() []string { return append([]string{a.ID}, a.Aliases...) }

// IsMalicious reports an OSV malicious-package record.
func (a Advisory) IsMalicious() bool {
	for _, id := range a.IDs() {
		if strings.HasPrefix(id, "MAL-") {
			return true
		}
	}
	return false
}
