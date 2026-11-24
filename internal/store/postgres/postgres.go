// Package postgres is the PostgreSQL store.Store (pgx, no CGO).
//
// Hot query fields are columns with indexes; each finding's full record is a
// jsonb document, so new model fields need no migration. The columns status,
// first_seen and last_seen are authoritative over the document.
//
// Config:
//
//	store:
//	  type: postgres
//	  dsn_env: HEIMDALL_PG_DSN   # or dsn_file; the DSN holds a password, never inline it
//	  schema: heimdall           # created by `heimdall db migrate`
//	  max_conns: 10
package postgres

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Advisory lock keys (arbitrary constants, unique to Heimdall).
const (
	migrateLockKey = 7_244_190_001
	recordLockKey  = 7_244_190_002
)

func init() { store.Registry.Register("postgres", New) }

// Config is the plugin's config block.
type Config struct {
	DSNEnv   string `mapstructure:"dsn_env"`
	DSNFile  string `mapstructure:"dsn_file"`
	Schema   string `mapstructure:"schema"`
	MaxConns int32  `mapstructure:"max_conns"`
}

var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Validate checks the config.
func (c *Config) Validate() error {
	if c.DSNEnv == "" && c.DSNFile == "" {
		return errors.New("dsn_env or dsn_file is required (the DSN holds a password: never inline it)")
	}
	if !identRe.MatchString(c.Schema) {
		return fmt.Errorf("schema %q must match %s", c.Schema, identRe)
	}
	if c.MaxConns <= 0 {
		return errors.New("max_conns must be > 0")
	}
	return nil
}

// Store implements store.Store.
type Store struct {
	pool   *pgxpool.Pool
	schema string
}

var _ store.Store = (*Store)(nil)

// New is the registry factory.
func New(raw plugin.Config, _ plugin.Deps) (store.Store, error) {
	cfg := Config{DSNEnv: "HEIMDALL_PG_DSN", Schema: "heimdall", MaxConns: 10}
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	dsn, err := secret.Resolve(cfg.DSNEnv, cfg.DSNFile)
	if err != nil {
		return nil, fmt.Errorf("postgres dsn: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return Open(ctx, dsn, cfg.Schema, cfg.MaxConns)
}

// Open connects with search_path set to schema. Errors never include the DSN.
func Open(ctx context.Context, dsn, schema string, maxConns int32) (*Store, error) {
	if !identRe.MatchString(schema) {
		return nil, fmt.Errorf("postgres: invalid schema %q", schema)
	}
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("postgres: invalid DSN")
	}
	pc.MaxConns = maxConns
	pc.ConnConfig.RuntimeParams["search_path"] = schema
	pc.ConnConfig.RuntimeParams["application_name"] = "heimdall"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	return &Store{pool: pool, schema: schema}, nil
}

// Close releases the pool. Safe to call twice.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// Migrate creates the schema and applies pending migrations in one
// transaction, serialised across processes by an advisory lock.
func (s *Store) Migrate(ctx context.Context) error {
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(migrateLockKey)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{s.schema}.Sanitize()); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return err
		}
		for _, f := range files {
			base := strings.TrimPrefix(f, "migrations/")
			v, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
			if err != nil {
				return fmt.Errorf("migration %s: name must start with a number", base)
			}
			var done bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", v).Scan(&done); err != nil {
				return err
			}
			if done {
				continue
			}
			sql, err := migrations.ReadFile(f)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("migration %s: %w", base, err)
			}
			if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", v); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---- runs ----

const runCols = "id, started_at, finished_at, status, targets, repos_scanned, repos_failed, sources, error"

func (s *Store) StartRun(ctx context.Context, run *model.ScanRun) error {
	run.Status = model.RunRunning
	src, err := json.Marshal(run.Sources)
	if err != nil {
		return err
	}
	return s.pool.QueryRow(ctx, `INSERT INTO scan_runs (started_at, status, targets, repos_scanned, repos_failed, sources, error)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		run.StartedAt, run.Status, nonNil(run.Targets), nonNil(run.ReposScanned), nonNil(run.ReposFailed), src, run.Error,
	).Scan(&run.ID)
}

func (s *Store) FinishRun(ctx context.Context, run *model.ScanRun) error {
	src, err := json.Marshal(run.Sources)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE scan_runs SET finished_at = $2, status = $3, targets = $4, repos_scanned = $5,
		repos_failed = $6, sources = $7, error = $8 WHERE id = $1`,
		run.ID, nullTime(run.FinishedAt), run.Status, nonNil(run.Targets), nonNil(run.ReposScanned), nonNil(run.ReposFailed), src, run.Error)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("run %d: %w", run.ID, store.ErrNotFound)
	}
	return nil
}

func (s *Store) GetRun(ctx context.Context, id int64) (*model.ScanRun, error) {
	r, err := scanRun(s.pool.QueryRow(ctx, "SELECT "+runCols+" FROM scan_runs WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("run %d: %w", id, store.ErrNotFound)
	}
	return r, err
}

func (s *Store) LatestRun(ctx context.Context, before int64) (*model.ScanRun, error) {
	r, err := scanRun(s.pool.QueryRow(ctx, "SELECT "+runCols+` FROM scan_runs
		WHERE status <> 'running' AND ($1 = 0 OR id < $1) ORDER BY id DESC LIMIT 1`, before))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("latest run: %w", store.ErrNotFound)
	}
	return r, err
}

func (s *Store) ListRuns(ctx context.Context, limit int) ([]model.ScanRun, error) {
	var lim any
	if limit > 0 {
		lim = limit
	}
	rows, err := s.pool.Query(ctx, "SELECT "+runCols+" FROM scan_runs ORDER BY id DESC LIMIT $1", lim)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ScanRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func scanRun(row pgx.Row) (*model.ScanRun, error) {
	var r model.ScanRun
	var finished *time.Time
	var src []byte
	if err := row.Scan(&r.ID, &r.StartedAt, &finished, &r.Status, &r.Targets, &r.ReposScanned, &r.ReposFailed, &src, &r.Error); err != nil {
		return nil, err
	}
	if finished != nil {
		r.FinishedAt = *finished
	}
	if err := json.Unmarshal(src, &r.Sources); err != nil {
		return nil, fmt.Errorf("decode run sources: %w", err)
	}
	return &r, nil
}

// ---- findings ----

var findingCols = []string{"id", "kind", "provider", "repo", "manifest_path", "ecosystem", "package_name",
	"package_version", "purl", "advisory_id", "severity", "severity_rank", "in_kev", "status", "first_seen",
	"last_seen", "data"}

// selectFinding reads a finding; columns override the document.
const selectFinding = "f.data, f.status, f.first_seen, f.last_seen"

func (s *Store) RecordFindings(ctx context.Context, runID int64, scanned []string, findings []model.Finding, at time.Time) (*model.Diff, error) {
	incoming := map[string]model.Finding{}
	for _, f := range findings {
		incoming[f.ID] = f
	}
	ids := make([]string, 0, len(incoming))
	for id := range incoming {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	diff := &model.Diff{ToRun: runID}

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// One writer at a time: two overlapping runs must not interleave
		// read-modify-write of the same findings.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(recordLockKey)); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM scan_runs WHERE id = $1)", runID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("run %d: %w", runID, store.ErrNotFound)
		}
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM scan_runs WHERE id < $1 AND status <> 'running'`, runID).Scan(&diff.FromRun); err != nil {
			return err
		}

		type prevState struct {
			status    model.FindingStatus
			firstSeen time.Time
		}
		prev := map[string]prevState{}
		rows, err := tx.Query(ctx, "SELECT id, status, first_seen FROM findings WHERE id = ANY($1)", ids)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			var p prevState
			if err := rows.Scan(&id, &p.status, &p.firstSeen); err != nil {
				rows.Close()
				return err
			}
			prev[id] = p
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		copyRows := make([][]any, 0, len(ids))
		for _, id := range ids {
			f := incoming[id]
			f.LastSeen = at
			p, seen := prev[id]
			switch {
			case !seen:
				f.FirstSeen, f.Status = at, model.StatusOpen
				diff.New = append(diff.New, f)
			case p.status == model.StatusSuppressed:
				f.FirstSeen, f.Status = p.firstSeen, model.StatusSuppressed
			case p.status == model.StatusFixed:
				f.FirstSeen, f.Status = p.firstSeen, model.StatusOpen
				diff.New = append(diff.New, f)
			default:
				f.FirstSeen, f.Status = p.firstSeen, model.StatusOpen
				diff.StillOpen = append(diff.StillOpen, f)
			}
			row, err := findingRow(f)
			if err != nil {
				return err
			}
			copyRows = append(copyRows, row)
		}

		if _, err := tx.Exec(ctx, "CREATE TEMP TABLE tmp_findings (LIKE findings INCLUDING DEFAULTS) ON COMMIT DROP"); err != nil {
			return err
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tmp_findings"}, findingCols, pgx.CopyFromRows(copyRows)); err != nil {
			return fmt.Errorf("copy findings: %w", err)
		}
		set := make([]string, 0, len(findingCols)-1)
		for _, c := range findingCols[1:] {
			set = append(set, c+" = EXCLUDED."+c)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO findings SELECT * FROM tmp_findings ON CONFLICT (id) DO UPDATE SET "+strings.Join(set, ", ")); err != nil {
			return fmt.Errorf("upsert findings: %w", err)
		}

		fixed, err := queryFindings(ctx, tx, `UPDATE findings f SET status = 'fixed'
			WHERE f.repo = ANY($1) AND f.status = 'open'
			  AND NOT EXISTS (SELECT 1 FROM tmp_findings t WHERE t.id = f.id)
			RETURNING `+selectFinding, nonNil(scanned))
		if err != nil {
			return fmt.Errorf("close fixed findings: %w", err)
		}
		sort.Slice(fixed, func(i, j int) bool { return fixed[i].ID < fixed[j].ID })
		diff.Fixed = fixed

		if _, err := tx.Exec(ctx, `INSERT INTO run_findings (run_id, finding_id)
			SELECT $1, id FROM tmp_findings WHERE status <> 'suppressed' ON CONFLICT DO NOTHING`, runID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO run_repos (run_id, repo) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING`, runID, nonNil(scanned))
		return err
	})
	if err != nil {
		return nil, err
	}
	return diff, nil
}

func findingRow(f model.Finding) ([]any, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("encode finding %s: %w", f.ID, err)
	}
	return []any{f.ID, string(f.Kind), f.Provider, f.Repo, f.ManifestPath, string(f.Package.Ecosystem), f.Package.Name,
		f.Package.Version, f.Package.PURL, f.AdvisoryID, string(f.Severity), int16(f.Severity.Rank()), f.InKEV,
		string(f.Status), f.FirstSeen, f.LastSeen, data}, nil
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func queryFindings(ctx context.Context, q querier, sql string, args ...any) ([]model.Finding, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

func scanFinding(row pgx.Row) (*model.Finding, error) {
	var data []byte
	var f model.Finding
	var status string
	var first, last time.Time
	if err := row.Scan(&data, &status, &first, &last); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("decode finding: %w", err)
	}
	f.Status, f.FirstSeen, f.LastSeen = model.FindingStatus(status), first, last
	return &f, nil
}

func (s *Store) ListFindings(ctx context.Context, flt store.FindingFilter) ([]model.Finding, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if flt.Repo != "" {
		add("f.repo = $%d", flt.Repo)
	}
	if flt.Kind != "" {
		add("f.kind = $%d", string(flt.Kind))
	}
	if flt.Status != "" {
		add("f.status = $%d", string(flt.Status))
	}
	if flt.MinSeverity != "" {
		add("f.severity_rank >= $%d", int16(flt.MinSeverity.Rank()))
	}
	if flt.InKEV {
		where = append(where, "f.in_kev")
	}
	if !flt.NewSince.IsZero() {
		add("f.first_seen >= $%d", flt.NewSince)
	}
	sql := "SELECT " + selectFinding + " FROM findings f"
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY f.severity_rank DESC, f.repo, f.id"
	if flt.Limit > 0 {
		args = append(args, flt.Limit)
		sql += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	return queryFindings(ctx, s.pool, sql, args...)
}

func (s *Store) GetFinding(ctx context.Context, id string) (*model.Finding, error) {
	f, err := scanFinding(s.pool.QueryRow(ctx, "SELECT "+selectFinding+" FROM findings f WHERE f.id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("finding %s: %w", id, store.ErrNotFound)
	}
	return f, err
}

func (s *Store) SetFindingStatus(ctx context.Context, id string, status model.FindingStatus) error {
	tag, err := s.pool.Exec(ctx, "UPDATE findings SET status = $2 WHERE id = $1", id, string(status))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("finding %s: %w", id, store.ErrNotFound)
	}
	return nil
}

func (s *Store) DiffRuns(ctx context.Context, from, to int64) (*model.Diff, error) {
	for _, id := range []int64{from, to} {
		var ok bool
		if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM scan_runs WHERE id = $1)", id).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("run %d: %w", id, store.ErrNotFound)
		}
	}
	d := &model.Diff{FromRun: from, ToRun: to}
	var err error
	const inRun = "SELECT 1 FROM run_findings x WHERE x.run_id = $%d AND x.finding_id = r.finding_id"
	d.New, err = queryFindings(ctx, s.pool, "SELECT "+selectFinding+` FROM run_findings r JOIN findings f ON f.id = r.finding_id
		WHERE r.run_id = $2 AND NOT EXISTS (`+fmt.Sprintf(inRun, 1)+`) ORDER BY f.id`, from, to)
	if err != nil {
		return nil, err
	}
	d.StillOpen, err = queryFindings(ctx, s.pool, "SELECT "+selectFinding+` FROM run_findings r JOIN findings f ON f.id = r.finding_id
		WHERE r.run_id = $2 AND EXISTS (`+fmt.Sprintf(inRun, 1)+`) ORDER BY f.id`, from, to)
	if err != nil {
		return nil, err
	}
	d.Fixed, err = queryFindings(ctx, s.pool, "SELECT "+selectFinding+` FROM run_findings r JOIN findings f ON f.id = r.finding_id
		WHERE r.run_id = $1 AND NOT EXISTS (`+fmt.Sprintf(inRun, 2)+`)
		  AND f.repo IN (SELECT repo FROM run_repos WHERE run_id = $2) ORDER BY f.id`, from, to)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// ---- repo state & notifications ----

func (s *Store) GetRepoState(ctx context.Context, repo, ref string) (*model.RepoState, error) {
	st := model.RepoState{Repo: repo, Ref: ref}
	err := s.pool.QueryRow(ctx, "SELECT head_sha, scanned_at FROM repo_states WHERE repo = $1 AND ref = $2", repo, ref).
		Scan(&st.HeadSHA, &st.ScannedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("repo state %s@%s: %w", repo, ref, store.ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *Store) PutRepoState(ctx context.Context, st model.RepoState) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO repo_states (repo, ref, head_sha, scanned_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (repo, ref) DO UPDATE SET head_sha = EXCLUDED.head_sha, scanned_at = EXCLUDED.scanned_at`,
		st.Repo, st.Ref, st.HeadSHA, st.ScannedAt)
	return err
}

func (s *Store) MarkNotified(ctx context.Context, key string, at time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, "INSERT INTO notifications (key, notified_at) VALUES ($1, $2) ON CONFLICT DO NOTHING", key, at)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
