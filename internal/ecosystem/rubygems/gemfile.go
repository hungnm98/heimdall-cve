package rubygems

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/version"
)

// gemDecl is one `gem` statement of a Gemfile.
type gemDecl struct {
	name    string
	reqs    []string // literal requirement strings, e.g. "~> 1.2", ">= 1.0"
	dynamic bool     // a requirement is not a string literal
	groups  []string // effective groups; empty means :default
	source  string   // srcGit / srcPath when not from a gem server
}

// frame is an open Ruby block.
type frame struct {
	groups []string
	source string
}

var (
	// doRe ends a line that opens a do-block ("do", "do |x|").
	doRe = regexp.MustCompile(`(^|\s)do(\s*\|[^|]*\|)?$`)
	// openerRe starts a statement that is closed by "end".
	openerRe = regexp.MustCompile(`^(if|unless|case|while|until|begin|def|class|module)\b`)
	endRe    = regexp.MustCompile(`^end\b`)
	// modifierRe is a trailing "if"/"unless" statement modifier.
	modifierRe = regexp.MustCompile(`\s+(if|unless)\s+.*$`)
	// stmtRe is a method call: "gem \"x\"", "gem(\"x\")", "group :test".
	stmtRe = regexp.MustCompile(`^([a-z_]+)(\s*\(.*\)|\s+.*|)$`)
)

// parseGemfile is a best-effort line parser of a Gemfile (see the package
// documentation for its limits).
func parseGemfile(data []byte) []gemDecl {
	var out []gemDecl
	stack := []frame{{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		text := strings.TrimSpace(stripComment(sc.Text()))
		if text == "" {
			continue
		}
		if endRe.MatchString(text) {
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		top := stack[len(stack)-1]
		opens := doRe.MatchString(text) || openerRe.MatchString(text)
		body := strings.TrimSpace(doRe.ReplaceAllString(text, ""))
		if !opens {
			body = modifierRe.ReplaceAllString(body, "") // gem "x" if cond
		}
		m := stmtRe.FindStringSubmatch(body)
		next := top
		if m != nil {
			args := splitArgs(strings.TrimSpace(trimParens(m[2])))
			switch m[1] {
			case "gem":
				if d, ok := gemStatement(args, top); ok {
					out = append(out, d)
				}
			case "group":
				next.groups = nil
				for _, a := range args {
					if g, ok := symbol(a); ok {
						next.groups = append(next.groups, g)
					}
				}
			case "git", "github", "gist", "bitbucket":
				next.source = srcGit
			case "path":
				next.source = srcPath
			}
		}
		if opens {
			stack = append(stack, next)
		}
	}
	return out
}

func gemStatement(args []string, top frame) (gemDecl, bool) {
	if len(args) == 0 {
		return gemDecl{}, false
	}
	name, ok := stringLit(args[0])
	if !ok || name == "" {
		return gemDecl{}, false
	}
	d := gemDecl{name: name, groups: append([]string(nil), top.groups...), source: top.source}
	for _, a := range args[1:] {
		if k, v, ok := keyword(a); ok {
			switch k {
			case "group", "groups":
				for _, g := range splitArgs(strings.Trim(v, "[] ")) {
					if s, ok := symbol(g); ok {
						d.groups = append(d.groups, s)
					}
				}
			case "git", "github", "gist", "bitbucket":
				d.source = srcGit
			case "path":
				d.source = srcPath
			}
			continue
		}
		if s, ok := stringLit(a); ok {
			d.reqs = append(d.reqs, s)
			continue
		}
		if strings.HasPrefix(a, "[") && strings.HasSuffix(a, "]") {
			for _, e := range splitArgs(strings.Trim(a, "[] ")) {
				if s, ok := stringLit(e); ok {
					d.reqs = append(d.reqs, s)
				} else {
					d.dynamic = true
				}
			}
			continue
		}
		d.dynamic = true
	}
	return d, true
}

// devGems returns the gems every declaration of which sits only in
// development/test groups.
func devGems(decls []gemDecl) map[string]bool {
	out := map[string]bool{}
	for _, d := range decls {
		isDev := len(d.groups) > 0
		for _, g := range d.groups {
			isDev = isDev && (g == "development" || g == "test")
		}
		if prev, seen := out[d.name]; seen {
			isDev = isDev && prev
		}
		out[d.name] = isDev
	}
	return out
}

var reqRe = regexp.MustCompile(`^(=|!=|>=|<=|>|<|~>)?\s*(\S+)$`)

// minVersion returns the minimum version satisfying literal requirements, or
// "" and the reason it cannot.
func minVersion(reqs []string) (string, string) {
	type req struct{ op, v string }
	var rs []req
	for _, s := range reqs {
		for _, part := range strings.Split(s, ",") { // "> 1, < 2" in one string
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			m := reqRe.FindStringSubmatch(part)
			if m == nil || !(version.RubyGems{}).Valid(m[2]) {
				return "", "unsupported constraint " + part
			}
			op := m[1]
			if op == "" {
				op = "="
			}
			rs = append(rs, req{op, m[2]})
		}
	}
	if len(rs) == 0 {
		return "", "no version constraint"
	}
	cmp := version.RubyGems{}
	best := ""
	for _, r := range rs {
		if (r.op == "=" || r.op == ">=" || r.op == "~>") && (best == "" || cmp.Compare(r.v, best) > 0) {
			best = r.v
		}
	}
	if best == "" {
		return "", "no lower bound in " + strings.Join(reqs, ", ")
	}
	for _, r := range rs {
		c := cmp.Compare(best, r.v)
		ok := true
		switch r.op {
		case "=":
			ok = c == 0
		case "!=":
			ok = c != 0
		case ">=":
			ok = c >= 0
		case ">":
			ok = c > 0
		case "<=":
			ok = c <= 0
		case "<":
			ok = c < 0
		case "~>":
			ok = c >= 0 && cmp.Compare(best, pessimisticUpper(r.v)) < 0
		}
		if !ok {
			return "", "unsupported constraint " + strings.Join(reqs, ", ")
		}
	}
	return best, ""
}

// pessimisticUpper is the exclusive upper bound of "~> v" (Gem::Version#bump):
// prerelease segments dropped, the last release segment dropped unless it is
// the only one, then the last one incremented. "1.2.3" → "1.3", "1.2" → "2".
func pessimisticUpper(v string) string {
	var segs []string
	for _, s := range strings.Split(v, ".") {
		if s == "" || strings.Trim(s, "0123456789") != "" {
			break
		}
		segs = append(segs, s)
	}
	if len(segs) > 1 {
		segs = segs[:len(segs)-1]
	}
	if len(segs) == 0 {
		return v
	}
	segs[len(segs)-1] = increment(segs[len(segs)-1])
	return strings.Join(segs, ".")
}

// increment adds one to a decimal string of any length.
func increment(n string) string {
	b := []byte(n)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < '9' {
			b[i]++
			return string(b)
		}
		b[i] = '0'
	}
	return "1" + string(b)
}

// stripComment drops a trailing "# ..." outside string literals.
func stripComment(l string) string {
	var quote byte
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return l[:i]
		}
	}
	return l
}

func trimParens(s string) string {
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		return s[1 : len(s)-1]
	}
	return s
}

// splitArgs splits on commas outside quotes and brackets.
func splitArgs(s string) []string {
	var out []string
	var quote byte
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '[' || c == '(' || c == '{':
			depth++
		case c == ']' || c == ')' || c == '}':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if last := strings.TrimSpace(s[start:]); last != "" {
		out = append(out, last)
	}
	return out
}

var (
	stringLitRe = regexp.MustCompile(`^(?:"([^"#\\]*)"|'([^'\\]*)')$`)
	symbolRe    = regexp.MustCompile(`^:(\w+)$`)
	// keywordRe matches "key: value", ":key => value" and "\"key\" => value".
	keywordRe = regexp.MustCompile(`^(?:(\w+):\s*|:(\w+)\s*=>\s*|["'](\w+)["']\s*=>\s*)(.*)$`)
)

func stringLit(s string) (string, bool) {
	m := stringLitRe.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1] + m[2], true
}

// symbol reads :name or a string literal.
func symbol(s string) (string, bool) {
	if m := symbolRe.FindStringSubmatch(s); m != nil {
		return m[1], true
	}
	return stringLit(s)
}

func keyword(s string) (string, string, bool) {
	m := keywordRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1] + m[2] + m[3], strings.TrimSpace(m[4]), true
}
