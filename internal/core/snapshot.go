package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// snapshotFormat changes when the snapshot encoding changes.
const snapshotFormat = "1"

// snapshotRetention: snapshots unused for this long are pruned.
const snapshotRetention = 30 * 24 * time.Hour

// snapshot is what reading and parsing one commit produced.
type snapshot struct {
	Graphs   []model.DependencyGraph `json:"graphs"`
	Runtimes []model.Runtime         `json:"runtimes"`
	Errs     []string                `json:"errs,omitempty"`
}

// fingerprint identifies everything besides the commit that shapes parser
// output: the build, the parsers and detectors in use, skip paths and
// SnapshotSalt (parser options such as private_modules).
func (p *Pipeline) fingerprint() string {
	parts := []string{snapshotFormat, buildID(), p.SnapshotSalt, strings.Join(p.SkipPaths, ",")}
	var names []string
	for _, e := range p.Ecosystems {
		names = append(names, "eco:"+string(e.Name()))
	}
	for _, d := range p.Detectors {
		names = append(names, "det:"+d.Name())
	}
	sort.Strings(names)
	h := sha256.Sum256([]byte(strings.Join(append(parts, names...), "\x00")))
	return hex.EncodeToString(h[:12])
}

// buildID identifies the binary: VCS revision, plus the executable's mtime
// for builds from a modified tree.
func buildID() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	id := bi.Main.Version
	modified := false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			id += "@" + s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if modified {
		if exe, err := os.Executable(); err == nil {
			if fi, err := os.Stat(exe); err == nil {
				id += "+" + fi.ModTime().UTC().Format(time.RFC3339Nano)
			}
		}
	}
	return id
}

func (p *Pipeline) snapshots() (store.Snapshots, bool) {
	s, ok := p.Store.(store.Snapshots)
	return s, ok
}

// loadSnapshot fills r from the snapshot of its commit; false on a miss.
func (p *Pipeline) loadSnapshot(ctx context.Context, r *repoResult) bool {
	ss, ok := p.snapshots()
	if !ok || r.sha == "" {
		return false
	}
	data, err := ss.GetSnapshot(ctx, r.repo.FullName(), r.sha, p.fingerprint(), p.now())
	if err != nil {
		return false
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return false
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return false
	}
	var snap snapshot
	if json.Unmarshal(raw, &snap) != nil {
		return false
	}
	r.graphs, r.runtimes, r.errs, r.cached = snap.Graphs, snap.Runtimes, append(r.errs, snap.Errs...), true
	return true
}

// saveSnapshot stores what r parsed; failures only cost a re-parse later.
func (p *Pipeline) saveSnapshot(ctx context.Context, r *repoResult) {
	ss, ok := p.snapshots()
	if !ok || r.sha == "" {
		return
	}
	raw, err := json.Marshal(snapshot{Graphs: r.graphs, Runtimes: r.runtimes, Errs: r.errs})
	if err != nil {
		return
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	if zw.Close() != nil {
		return
	}
	now := p.now()
	if err := ss.PutSnapshot(ctx, r.repo.FullName(), r.sha, p.fingerprint(), buf.Bytes(), now, now.Add(-snapshotRetention)); err != nil {
		p.log().Warn("save commit snapshot", "repo", r.repo.FullName(), "err", err)
	}
}
