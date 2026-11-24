// Package prompts embeds the agent routines in this directory so that
// `heimdall mcp` serves them as MCP prompts. The Markdown files are the single
// source: humans read them here, agents get them through prompts/get.
package prompts

import (
	"embed"
	"io/fs"
	"sort"
	"strings"
)

//go:embed *.md
var files embed.FS

// Prompt is one routine.
type Prompt struct {
	Name  string // file name without .md, e.g. "daily-scan"
	Title string // first Markdown heading
	Text  string
}

// All returns every prompt, sorted by name.
func All() []Prompt {
	entries, _ := fs.Glob(files, "*.md")
	sort.Strings(entries)
	out := make([]Prompt, 0, len(entries))
	for _, e := range entries {
		b, err := files.ReadFile(e)
		if err != nil {
			continue
		}
		text := string(b)
		title, _, _ := strings.Cut(text, "\n")
		out = append(out, Prompt{
			Name:  strings.TrimSuffix(e, ".md"),
			Title: strings.TrimSpace(strings.TrimPrefix(title, "#")),
			Text:  text,
		})
	}
	return out
}
