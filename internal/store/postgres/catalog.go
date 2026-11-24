package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var _ store.Catalog = (*Store)(nil)

// SQLSTATE codes mapped to store errors.
const (
	codeUniqueViolation = "23505"
	codeFKViolation     = "23503"
)

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func notFound(what string, id any) error { return fmt.Errorf("%s %v: %w", what, id, store.ErrNotFound) }

// limitArg turns "0 = no limit" into a NULL LIMIT.
func limitArg(n int) any {
	if n > 0 {
		return n
	}
	return nil
}

// jsonDoc encodes v for a NOT NULL jsonb column: nil maps become {}.
func jsonDoc[M ~map[string]any](m M) ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

// ---- auth profiles ----

const profileCols = "id, name, type, options, secret_id, secret_fingerprint, origin, created_at, updated_at"

func scanProfile(row pgx.Row) (*model.AuthProfile, error) {
	var p model.AuthProfile
	var opts []byte
	var origin string
	if err := row.Scan(&p.ID, &p.Name, &p.Type, &opts, &p.SecretID, &p.SecretFingerprint, &origin, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(opts, &p.Options); err != nil {
		return nil, fmt.Errorf("decode auth profile %s options: %w", p.Name, err)
	}
	p.Origin = model.Origin(origin)
	return &p, nil
}

func (s *Store) ListAuthProfiles(ctx context.Context) ([]model.AuthProfile, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+profileCols+" FROM auth_profiles ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuthProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *Store) GetAuthProfile(ctx context.Context, name string) (*model.AuthProfile, error) {
	p, err := scanProfile(s.pool.QueryRow(ctx, "SELECT "+profileCols+" FROM auth_profiles WHERE name = $1", name))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("auth profile", name)
	}
	return p, err
}

// SaveAuthProfile inserts or updates; a rename cascades into targets through
// the ON UPDATE CASCADE foreign keys.
func (s *Store) SaveAuthProfile(ctx context.Context, p *model.AuthProfile) error {
	opts, err := jsonDoc(p.Options)
	if err != nil {
		return fmt.Errorf("encode auth profile options: %w", err)
	}
	if p.ID == 0 {
		err = s.pool.QueryRow(ctx, `INSERT INTO auth_profiles (name, type, options, secret_id, secret_fingerprint, origin)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at, updated_at`,
			p.Name, p.Type, opts, p.SecretID, p.SecretFingerprint, string(p.Origin)).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	} else {
		err = s.pool.QueryRow(ctx, `UPDATE auth_profiles SET name = $2, type = $3, options = $4, secret_id = $5,
			secret_fingerprint = $6, origin = $7, updated_at = now() WHERE id = $1 RETURNING created_at, updated_at`,
			p.ID, p.Name, p.Type, opts, p.SecretID, p.SecretFingerprint, string(p.Origin)).Scan(&p.CreatedAt, &p.UpdatedAt)
	}
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return notFound("auth profile", p.ID)
	case pgCode(err) == codeUniqueViolation:
		return fmt.Errorf("auth profile %q: %w", p.Name, store.ErrConflict)
	case pgCode(err) == codeFKViolation:
		return fmt.Errorf("auth profile %q: unknown secret: %w", p.Name, store.ErrConflict)
	}
	return err
}

func (s *Store) DeleteAuthProfile(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM auth_profiles WHERE name = $1", name)
	if pgCode(err) == codeFKViolation {
		return fmt.Errorf("auth profile %q is used by a target: %w", name, store.ErrConflict)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return notFound("auth profile", name)
	}
	return nil
}

// ---- secrets ----

const secretCols = "id, kind, kek_id, wrapped_dek, ciphertext, fingerprint, created_at, rotated_at"

func scanSecret(row pgx.Row) (*store.SecretRecord, error) {
	var r store.SecretRecord
	if err := row.Scan(&r.ID, &r.Kind, &r.Sealed.KEKID, &r.Sealed.WrappedDEK, &r.Sealed.Ciphertext, &r.Fingerprint,
		&r.CreatedAt, &r.RotatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) SaveSecret(ctx context.Context, r *store.SecretRecord) error {
	var err error
	if r.ID == 0 {
		err = s.pool.QueryRow(ctx, `INSERT INTO secrets (kind, kek_id, wrapped_dek, ciphertext, fingerprint, rotated_at)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
			r.Kind, r.Sealed.KEKID, r.Sealed.WrappedDEK, r.Sealed.Ciphertext, r.Fingerprint, r.RotatedAt).Scan(&r.ID, &r.CreatedAt)
	} else {
		err = s.pool.QueryRow(ctx, `UPDATE secrets SET kind = $2, kek_id = $3, wrapped_dek = $4, ciphertext = $5,
			fingerprint = $6, rotated_at = $7 WHERE id = $1 RETURNING created_at`,
			r.ID, r.Kind, r.Sealed.KEKID, r.Sealed.WrappedDEK, r.Sealed.Ciphertext, r.Fingerprint, r.RotatedAt).Scan(&r.CreatedAt)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return notFound("secret", r.ID)
	}
	return err
}

func (s *Store) GetSecret(ctx context.Context, id int64) (*store.SecretRecord, error) {
	r, err := scanSecret(s.pool.QueryRow(ctx, "SELECT "+secretCols+" FROM secrets WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("secret", id)
	}
	return r, err
}

func (s *Store) ListSecrets(ctx context.Context) ([]store.SecretRecord, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+secretCols+" FROM secrets ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.SecretRecord
	for rows.Next() {
		r, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSecret(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM secrets WHERE id = $1", id)
	if pgCode(err) == codeFKViolation {
		return fmt.Errorf("secret %d is used by an auth profile: %w", id, store.ErrConflict)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return notFound("secret", id)
	}
	return nil
}

// ---- targets ----

const targetCols = "id, kind, provider, base_url, owner, name, branch, auth, list_auth, repos, filter, schedule, enabled, origin, next_run_at, created_at, updated_at"

func scanTarget(row pgx.Row) (*model.TargetSpec, error) {
	var t model.TargetSpec
	var kind, origin string
	var filter []byte
	if err := row.Scan(&t.ID, &kind, &t.Provider, &t.BaseURL, &t.Owner, &t.Name, &t.Branch, &t.Auth, &t.ListAuth,
		&t.Repos, &filter, &t.Schedule, &t.Enabled, &origin, &t.NextRunAt, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(filter, &t.Filter); err != nil {
		return nil, fmt.Errorf("decode target %d filter: %w", t.ID, err)
	}
	t.Kind, t.Origin = model.TargetKind(kind), model.Origin(origin)
	return &t, nil
}

func (s *Store) queryTargets(ctx context.Context, sql string, args ...any) ([]model.TargetSpec, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.TargetSpec
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *Store) ListTargets(ctx context.Context, f store.TargetFilter) ([]model.TargetSpec, error) {
	return s.queryTargets(ctx, "SELECT "+targetCols+` FROM targets
		WHERE ($1::boolean IS NULL OR enabled = $1) AND ($2 = '' OR origin = $2) ORDER BY id`, f.Enabled, string(f.Origin))
}

func (s *Store) GetTarget(ctx context.Context, id int64) (*model.TargetSpec, error) {
	t, err := scanTarget(s.pool.QueryRow(ctx, "SELECT "+targetCols+" FROM targets WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("target", id)
	}
	return t, err
}

func (s *Store) SaveTarget(ctx context.Context, t *model.TargetSpec) error {
	filter, err := json.Marshal(t.Filter)
	if err != nil {
		return fmt.Errorf("encode target filter: %w", err)
	}
	args := []any{string(t.Kind), t.Provider, t.BaseURL, t.Owner, t.Name, t.Branch, t.Auth, t.ListAuth, nonNil(t.Repos),
		filter, t.Schedule, t.Enabled, string(t.Origin), t.NextRunAt}
	if t.ID == 0 {
		err = s.pool.QueryRow(ctx, `INSERT INTO targets (kind, provider, base_url, owner, name, branch, auth, list_auth,
			repos, filter, schedule, enabled, origin, next_run_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id, created_at, updated_at`,
			args...).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
	} else {
		err = s.pool.QueryRow(ctx, `UPDATE targets SET kind = $1, provider = $2, base_url = $3, owner = $4, name = $5,
			branch = $6, auth = $7, list_auth = $8, repos = $9, filter = $10, schedule = $11, enabled = $12, origin = $13,
			next_run_at = $14, updated_at = now() WHERE id = $15 RETURNING created_at, updated_at`,
			append(args, t.ID)...).Scan(&t.CreatedAt, &t.UpdatedAt)
	}
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return notFound("target", t.ID)
	case pgCode(err) == codeFKViolation:
		return fmt.Errorf("target %s: auth profile %q or %q does not exist: %w", t.Target, t.Auth, t.ListAuth, store.ErrConflict)
	}
	return err
}

// DeleteTarget removes a target and its cached repos. Its active jobs are
// canceled first: scan_jobs.target_id is ON DELETE SET NULL, and a queued job
// with a NULL target would otherwise read as "scan every target".
func (s *Store) DeleteTarget(ctx context.Context, id int64) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE scan_jobs SET status = 'canceled', error = 'target deleted', finished_at = now()
			WHERE target_id = $1 AND status IN ('queued', 'running')`, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM targets WHERE id = $1", id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return notFound("target", id)
		}
		return nil
	})
}

func (s *Store) DueTargets(ctx context.Context, now time.Time) ([]model.TargetSpec, error) {
	return s.queryTargets(ctx, "SELECT "+targetCols+` FROM targets
		WHERE enabled AND next_run_at <= $1 ORDER BY next_run_at, id`, now)
}

// ---- repos ----

func (s *Store) UpsertRepos(ctx context.Context, targetID int64, repos []model.Repo, at time.Time) error {
	// Last entry wins for duplicate names: one INSERT ... ON CONFLICT cannot
	// touch the same row twice.
	idx := map[string]int{}
	var names, docs []string
	for _, r := range repos {
		data, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("encode repo %s: %w", r.FullName(), err)
		}
		if i, ok := idx[r.FullName()]; ok {
			docs[i] = string(data)
			continue
		}
		idx[r.FullName()] = len(names)
		names = append(names, r.FullName())
		docs = append(docs, string(data))
	}
	if len(names) == 0 {
		var ok bool
		if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM targets WHERE id = $1)", targetID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return notFound("target", targetID)
		}
		return nil
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO repos (full_name, target_id, data, last_listed_at)
		SELECT n, $2, d::jsonb, $4 FROM unnest($1::text[], $3::text[]) AS u(n, d)
		ON CONFLICT (full_name) DO UPDATE SET target_id = EXCLUDED.target_id, data = EXCLUDED.data,
			last_listed_at = EXCLUDED.last_listed_at`, names, targetID, docs, at)
	if pgCode(err) == codeFKViolation {
		return notFound("target", targetID)
	}
	return err
}

const repoCols = "data, target_id, last_listed_at, last_head_sha, last_scanned_at"

func scanRepo(row pgx.Row) (*model.RepoRecord, error) {
	var r model.RepoRecord
	var data []byte
	if err := row.Scan(&data, &r.TargetID, &r.LastListedAt, &r.LastHeadSHA, &r.LastScannedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &r.Repo); err != nil {
		return nil, fmt.Errorf("decode repo: %w", err)
	}
	return &r, nil
}

func (s *Store) ListRepos(ctx context.Context, f store.RepoFilter) ([]model.RepoRecord, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.TargetID != 0 {
		add("target_id = $%d", f.TargetID)
	}
	if f.Query != "" {
		add("strpos(lower(full_name), lower($%d)) > 0", f.Query)
	}
	if f.After != "" {
		add("full_name > $%d", f.After) // keyset on the primary key
	}
	sql := "SELECT " + repoCols + " FROM repos"
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limitArg(f.Limit))
	sql += fmt.Sprintf(" ORDER BY full_name LIMIT $%d", len(args))
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.RepoRecord
	for rows.Next() {
		r, err := scanRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (s *Store) GetRepo(ctx context.Context, fullName string) (*model.RepoRecord, error) {
	r, err := scanRepo(s.pool.QueryRow(ctx, "SELECT "+repoCols+" FROM repos WHERE full_name = $1", fullName))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("repo", fullName)
	}
	return r, err
}

func (s *Store) MarkRepoScanned(ctx context.Context, fullName, headSHA string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, "UPDATE repos SET last_head_sha = $2, last_scanned_at = $3 WHERE full_name = $1", fullName, headSHA, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return notFound("repo", fullName)
	}
	return nil
}

// ---- jobs ----

const jobCols = "id, target_id, repo, branch, auth_profile, trigger, status, run_id, attempts, requested_by, error, created_at, started_at, finished_at"

func scanJob(row pgx.Row) (*model.Job, error) {
	var j model.Job
	var trigger, status string
	if err := row.Scan(&j.ID, &j.TargetID, &j.Repo, &j.Branch, &j.AuthProfile, &trigger, &status, &j.RunID, &j.Attempts,
		&j.RequestedBy, &j.Error, &j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
		return nil, err
	}
	j.Trigger, j.Status = model.JobTrigger(trigger), model.JobStatus(status)
	return &j, nil
}

// CreateJob relies on the unique partial index scan_jobs_active_scope_idx:
// concurrent callers race on the INSERT, exactly one wins and the others read
// the winner back. If the winner finishes between our INSERT and SELECT, the
// scope is free again and we retry the INSERT.
func (s *Store) CreateJob(ctx context.Context, j *model.Job) (bool, error) {
	if j.Status == "" {
		j.Status = model.JobQueued
	}
	for attempt := 0; attempt < 5; attempt++ {
		err := s.pool.QueryRow(ctx, `INSERT INTO scan_jobs (target_id, repo, branch, auth_profile, trigger, status, run_id,
			attempts, requested_by, error, started_at, finished_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT DO NOTHING RETURNING id, created_at`,
			j.TargetID, j.Repo, j.Branch, j.AuthProfile, string(j.Trigger), string(j.Status), j.RunID, j.Attempts,
			j.RequestedBy, j.Error, j.StartedAt, j.FinishedAt).Scan(&j.ID, &j.CreatedAt)
		switch {
		case err == nil:
			return true, nil
		case pgCode(err) == codeFKViolation:
			return false, notFound("target", deref(j.TargetID))
		case !errors.Is(err, pgx.ErrNoRows):
			return false, err
		}
		active, err := scanJob(s.pool.QueryRow(ctx, "SELECT "+jobCols+` FROM scan_jobs
			WHERE COALESCE(target_id, 0) = COALESCE($1, 0) AND repo = $2 AND status IN ('queued', 'running')`, j.TargetID, j.Repo))
		if errors.Is(err, pgx.ErrNoRows) {
			continue // the active job finished meanwhile
		}
		if err != nil {
			return false, err
		}
		*j = *active
		return false, nil
	}
	return false, errors.New("create job: scope keeps changing, giving up")
}

func deref(p *int64) any {
	if p == nil {
		return "<all>"
	}
	return *p
}

func (s *Store) GetJob(ctx context.Context, id int64) (*model.Job, error) {
	j, err := scanJob(s.pool.QueryRow(ctx, "SELECT "+jobCols+" FROM scan_jobs WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("job", id)
	}
	return j, err
}

func (s *Store) ListJobs(ctx context.Context, f store.JobFilter) ([]model.Job, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.Status != "" {
		add("status = $%d", string(f.Status))
	}
	if f.TargetID != 0 {
		add("target_id = $%d", f.TargetID)
	}
	if f.BeforeID != 0 {
		add("id < $%d", f.BeforeID)
	}
	sql := "SELECT " + jobCols + " FROM scan_jobs"
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limitArg(f.Limit))
	sql += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

func (s *Store) UpdateJob(ctx context.Context, j *model.Job) error {
	err := s.pool.QueryRow(ctx, `UPDATE scan_jobs SET status = $2, run_id = $3, attempts = $4, error = $5,
		started_at = $6, finished_at = $7 WHERE id = $1 RETURNING created_at`,
		j.ID, string(j.Status), j.RunID, j.Attempts, j.Error, j.StartedAt, j.FinishedAt).Scan(&j.CreatedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return notFound("job", j.ID)
	case pgCode(err) == codeUniqueViolation:
		return fmt.Errorf("job %d: another job with the same scope is active: %w", j.ID, store.ErrConflict)
	}
	return err
}

func (s *Store) AppendJobEvent(ctx context.Context, e *model.JobEvent) error {
	err := s.pool.QueryRow(ctx, `INSERT INTO job_events (job_id, at, level, repo, message)
		VALUES ($1, COALESCE($2::timestamptz, now()), $3, $4, $5) RETURNING id, at`,
		e.JobID, nullTime(e.At), e.Level, e.Repo, e.Message).Scan(&e.ID, &e.At)
	if pgCode(err) == codeFKViolation {
		return notFound("job", e.JobID)
	}
	return err
}

func (s *Store) ListJobEvents(ctx context.Context, jobID, afterID int64, limit int) ([]model.JobEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, job_id, at, level, repo, message FROM job_events
		WHERE job_id = $1 AND id > $2 ORDER BY id LIMIT $3`, jobID, afterID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.JobEvent
	for rows.Next() {
		var e model.JobEvent
		if err := rows.Scan(&e.ID, &e.JobID, &e.At, &e.Level, &e.Repo, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- suppressions ----

func (s *Store) SaveSuppression(ctx context.Context, sp *model.Suppression) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO suppressions (finding_id, reason, expires_at, actor, created_at)
			VALUES ($1, $2, $3, $4, COALESCE($5::timestamptz, now()))
			ON CONFLICT (finding_id) DO UPDATE SET reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at,
				actor = EXCLUDED.actor
			RETURNING created_at`, sp.FindingID, sp.Reason, sp.ExpiresAt, sp.Actor, nullTime(sp.CreatedAt)).Scan(&sp.CreatedAt)
		if pgCode(err) == codeFKViolation {
			return notFound("finding", sp.FindingID)
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE findings SET status = 'suppressed' WHERE id = $1", sp.FindingID)
		return err
	})
}

func (s *Store) GetSuppression(ctx context.Context, findingID string) (*model.Suppression, error) {
	var sp model.Suppression
	err := s.pool.QueryRow(ctx, `SELECT finding_id, reason, expires_at, actor, created_at FROM suppressions
		WHERE finding_id = $1`, findingID).Scan(&sp.FindingID, &sp.Reason, &sp.ExpiresAt, &sp.Actor, &sp.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("suppression", findingID)
	}
	if err != nil {
		return nil, err
	}
	return &sp, nil
}

func (s *Store) DeleteSuppression(ctx context.Context, findingID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM suppressions WHERE finding_id = $1", findingID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return notFound("suppression", findingID)
		}
		_, err = tx.Exec(ctx, "UPDATE findings SET status = 'open' WHERE id = $1 AND status = 'suppressed'", findingID)
		return err
	})
}

func (s *Store) ExpiredSuppressions(ctx context.Context, now time.Time) ([]model.Suppression, error) {
	rows, err := s.pool.Query(ctx, `SELECT finding_id, reason, expires_at, actor, created_at FROM suppressions
		WHERE expires_at <= $1 ORDER BY finding_id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Suppression
	for rows.Next() {
		var sp model.Suppression
		if err := rows.Scan(&sp.FindingID, &sp.Reason, &sp.ExpiresAt, &sp.Actor, &sp.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

// ---- audit ----

func (s *Store) AppendAudit(ctx context.Context, e *model.AuditEntry) error {
	details, err := jsonDoc(e.Details)
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}
	return s.pool.QueryRow(ctx, `INSERT INTO audit_log (at, actor, action, object_type, object_id, details)
		VALUES (COALESCE($1::timestamptz, now()), $2, $3, $4, $5, $6) RETURNING id, at`,
		nullTime(e.At), e.Actor, e.Action, e.ObjectType, e.ObjectID, details).Scan(&e.ID, &e.At)
}

func (s *Store) ListAudit(ctx context.Context, beforeID int64, limit int) ([]model.AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, at, actor, action, object_type, object_id, details FROM audit_log
		WHERE ($1 = 0 OR id < $1) ORDER BY id DESC LIMIT $2`, beforeID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		var details []byte
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.ObjectType, &e.ObjectID, &details); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(details, &e.Details); err != nil {
			return nil, fmt.Errorf("decode audit %d details: %w", e.ID, err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
