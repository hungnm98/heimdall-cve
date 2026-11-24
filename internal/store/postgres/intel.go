package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/jackc/pgx/v5"
)

var _ store.Intel = (*Store)(nil)

// inventoryLockClass is the first key of the two-key advisory lock that
// serialises ReplaceInventory per repo (second key: hashtext(repo)).
const inventoryLockClass = 72_441_903

var inventoryCols = []string{"repo", "manifest_path", "ecosystem", "name", "version", "purl", "direct", "scope",
	"private", "unresolvable", "scanned_at"}

// ---- inventory ----

func (s *Store) ReplaceInventory(ctx context.Context, repo string, items []model.InventoryItem, at time.Time) error {
	rows := make([][]any, len(items))
	for i, it := range items {
		rows[i] = []any{repo, it.ManifestPath, string(it.Package.Ecosystem), it.Package.Name, it.Package.Version,
			it.Package.PURL, it.Direct, string(it.Scope), it.Private, it.Unresolvable, at}
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Two concurrent replaces of one repo must not both delete the old
		// rows and then both insert: the later one wins whole.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1, hashtext($2))", int32(inventoryLockClass), repo); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM inventory WHERE repo = $1", repo); err != nil {
			return fmt.Errorf("delete inventory: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"inventory"}, inventoryCols, pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("copy inventory: %w", err)
		}
		return nil
	})
}

func (s *Store) ListInventory(ctx context.Context, f store.InventoryFilter) ([]model.InventoryItem, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.Repo != "" {
		add("repo = $%d", f.Repo)
	}
	if f.Ecosystem != "" {
		add("ecosystem = $%d", string(f.Ecosystem))
	}
	if f.Name != "" {
		add("name = $%d", f.Name)
	}
	if f.DirectOnly {
		where = append(where, "direct")
	}
	sql := "SELECT repo, manifest_path, ecosystem, name, version, purl, direct, scope, private, unresolvable FROM inventory"
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY repo, manifest_path, ecosystem, name, version"
	if f.Limit > 0 {
		args = append(args, f.Limit)
		sql += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.InventoryItem
	for rows.Next() {
		var it model.InventoryItem
		var eco, scope string
		if err := rows.Scan(&it.Repo, &it.ManifestPath, &eco, &it.Package.Name, &it.Package.Version, &it.Package.PURL,
			&it.Direct, &scope, &it.Private, &it.Unresolvable); err != nil {
			return nil, err
		}
		it.Package.Ecosystem, it.Scope = model.Ecosystem(eco), model.Scope(scope)
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) PackageUsage(ctx context.Context, f store.UsageFilter) ([]model.PackageUsage, error) {
	where := []string{"NOT private", "unresolvable = ''"} // matches inventory_usage_idx
	var args []any
	if f.Ecosystem != "" {
		args = append(args, string(f.Ecosystem))
		where = append(where, fmt.Sprintf("ecosystem = $%d", len(args)))
	}
	sql := `SELECT ecosystem, name, array_agg(DISTINCT version ORDER BY version), array_agg(DISTINCT repo ORDER BY repo), bool_or(direct)
		FROM inventory WHERE ` + strings.Join(where, " AND ") + " GROUP BY ecosystem, name"
	if f.DirectOnly {
		sql += " HAVING bool_or(direct)"
	}
	sql += " ORDER BY count(DISTINCT repo) DESC, ecosystem, name"
	if f.Limit > 0 {
		args = append(args, f.Limit)
		sql += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.PackageUsage
	for rows.Next() {
		var u model.PackageUsage
		var eco string
		if err := rows.Scan(&eco, &u.Name, &u.Versions, &u.Repos, &u.Direct); err != nil {
			return nil, err
		}
		u.Ecosystem = model.Ecosystem(eco)
		out = append(out, u)
	}
	return out, rows.Err()
}

// ---- agent advisories ----

func (s *Store) SaveAgentAdvisory(ctx context.Context, a *model.AgentAdvisory) error {
	doc, err := json.Marshal(a.Advisory)
	if err != nil {
		return fmt.Errorf("encode agent advisory %s: %w", a.Advisory.ID, err)
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO agent_advisories (id, advisory, evidence, confidence, submitted_by, submitted_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET advisory = EXCLUDED.advisory, evidence = EXCLUDED.evidence,
			confidence = EXCLUDED.confidence, submitted_by = EXCLUDED.submitted_by, submitted_at = EXCLUDED.submitted_at`,
		a.Advisory.ID, doc, nonNil(a.Evidence), string(a.Confidence), a.SubmittedBy, a.SubmittedAt)
	return err
}

func (s *Store) ListAgentAdvisories(ctx context.Context) ([]model.AgentAdvisory, error) {
	rows, err := s.pool.Query(ctx, `SELECT advisory, evidence, confidence, submitted_by, submitted_at
		FROM agent_advisories ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AgentAdvisory{}
	for rows.Next() {
		var a model.AgentAdvisory
		var doc []byte
		var conf string
		if err := rows.Scan(&doc, &a.Evidence, &conf, &a.SubmittedBy, &a.SubmittedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(doc, &a.Advisory); err != nil {
			return nil, fmt.Errorf("decode agent advisory: %w", err)
		}
		a.Confidence = model.Confidence(conf)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- library analyses ----

const analysisCols = "id, ecosystem, name, version, verdict, summary, evidence, recommended_version, confidence, agent, analyzed_at"

func (s *Store) SaveAnalysis(ctx context.Context, a *model.LibraryAnalysis) error {
	return s.pool.QueryRow(ctx, `INSERT INTO library_analyses
		(ecosystem, name, version, verdict, summary, evidence, recommended_version, confidence, agent, analyzed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		string(a.Ecosystem), a.Name, a.Version, string(a.Verdict), a.Summary, nonNil(a.Evidence), a.RecommendedVersion,
		string(a.Confidence), a.Agent, a.AnalyzedAt,
	).Scan(&a.ID)
}

func (s *Store) LatestAnalyses(ctx context.Context, f store.AnalysisFilter) ([]model.LibraryAnalysis, error) {
	// Ecosystem/name select whole groups, so they filter before DISTINCT ON;
	// the verdict filter applies to the newest analysis only, so it filters after.
	var inner, outer []string
	var args []any
	if f.Ecosystem != "" {
		args = append(args, string(f.Ecosystem))
		inner = append(inner, fmt.Sprintf("ecosystem = $%d", len(args)))
	}
	if f.Name != "" {
		args = append(args, f.Name)
		inner = append(inner, fmt.Sprintf("name = $%d", len(args)))
	}
	if f.Verdict != "" {
		args = append(args, string(f.Verdict))
		outer = append(outer, fmt.Sprintf("verdict = $%d", len(args)))
	}
	sql := "SELECT DISTINCT ON (ecosystem, name) " + analysisCols + " FROM library_analyses"
	if len(inner) > 0 {
		sql += " WHERE " + strings.Join(inner, " AND ")
	}
	sql = "SELECT " + analysisCols + " FROM (" + sql + " ORDER BY ecosystem, name, id DESC) l"
	if len(outer) > 0 {
		sql += " WHERE " + strings.Join(outer, " AND ")
	}
	sql += " ORDER BY ecosystem, name"
	if f.Limit > 0 {
		args = append(args, f.Limit)
		sql += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	return s.queryAnalyses(ctx, sql, args...)
}

func (s *Store) AnalysisHistory(ctx context.Context, eco model.Ecosystem, name string, limit int) ([]model.LibraryAnalysis, error) {
	var lim any
	if limit > 0 {
		lim = limit
	}
	return s.queryAnalyses(ctx, "SELECT "+analysisCols+` FROM library_analyses
		WHERE ecosystem = $1 AND name = $2 ORDER BY id DESC LIMIT $3`, string(eco), name, lim)
}

func (s *Store) queryAnalyses(ctx context.Context, sql string, args ...any) ([]model.LibraryAnalysis, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.LibraryAnalysis
	for rows.Next() {
		var a model.LibraryAnalysis
		var eco, verdict, conf string
		if err := rows.Scan(&a.ID, &eco, &a.Name, &a.Version, &verdict, &a.Summary, &a.Evidence, &a.RecommendedVersion,
			&conf, &a.Agent, &a.AnalyzedAt); err != nil {
			return nil, err
		}
		a.Ecosystem, a.Verdict, a.Confidence = model.Ecosystem(eco), model.Verdict(verdict), model.Confidence(conf)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- finding assessments ----

const assessmentCols = "id, advisory_id, ecosystem, package, version, repo, decision, score, rationale, evidence, confidence, inputs_hash, assessed_by, assessed_at"

func (s *Store) SaveAssessment(ctx context.Context, a *model.FindingAssessment) error {
	return s.pool.QueryRow(ctx, `INSERT INTO finding_assessments
		(advisory_id, ecosystem, package, version, repo, decision, score, rationale, evidence, confidence, inputs_hash, assessed_by, assessed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id`,
		a.AdvisoryID, string(a.Ecosystem), a.Package, a.Version, a.Repo, string(a.Decision), a.Score, a.Rationale,
		nonNil(a.Evidence), string(a.Confidence), a.InputsHash, a.AssessedBy, a.AssessedAt,
	).Scan(&a.ID)
}

func (s *Store) LatestAssessments(ctx context.Context, keys []model.AssessmentKey) ([]model.FindingAssessment, error) {
	var advs, ecos, pkgs, vers, repos []string
	seen := make(map[model.AssessmentKey]bool, len(keys))
	for _, k := range keys {
		if seen[k] {
			continue
		}
		seen[k] = true
		advs, ecos, pkgs, vers, repos = append(advs, k.AdvisoryID), append(ecos, string(k.Ecosystem)), append(pkgs, k.Package),
			append(vers, k.Version), append(repos, k.Repo)
	}
	if len(advs) == 0 {
		return nil, nil
	}
	// Per key: the newest repo-agnostic row and the newest row of the key's
	// repo, each one index probe on finding_assessments_key_idx. DISTINCT ON
	// drops the repo-agnostic row selected by several keys.
	const match = "a.advisory_id = k.k_adv AND a.ecosystem = k.k_eco AND a.package = k.k_pkg AND a.version = k.k_ver"
	sql := "SELECT DISTINCT ON (advisory_id, ecosystem, package, version, repo) " + assessmentCols + `
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[]) AS k(k_adv, k_eco, k_pkg, k_ver, k_repo)
		CROSS JOIN LATERAL (
			(SELECT ` + assessmentCols + " FROM finding_assessments a WHERE " + match + ` AND a.repo = '' ORDER BY a.id DESC LIMIT 1)
			UNION ALL
			(SELECT ` + assessmentCols + " FROM finding_assessments a WHERE " + match + ` AND k.k_repo <> '' AND a.repo = k.k_repo ORDER BY a.id DESC LIMIT 1)
		) x
		ORDER BY advisory_id, ecosystem, package, version, repo`
	return s.queryAssessments(ctx, sql, advs, ecos, pkgs, vers, repos)
}

func (s *Store) AssessmentHistory(ctx context.Context, k model.AssessmentKey, limit int) ([]model.FindingAssessment, error) {
	var lim any
	if limit > 0 {
		lim = limit
	}
	return s.queryAssessments(ctx, "SELECT "+assessmentCols+` FROM finding_assessments
		WHERE advisory_id = $1 AND ecosystem = $2 AND package = $3 AND version = $4 AND (repo = '' OR repo = $5)
		ORDER BY id DESC LIMIT $6`, k.AdvisoryID, string(k.Ecosystem), k.Package, k.Version, k.Repo, lim)
}

func (s *Store) queryAssessments(ctx context.Context, sql string, args ...any) ([]model.FindingAssessment, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.FindingAssessment
	for rows.Next() {
		var a model.FindingAssessment
		var eco, decision, conf string
		if err := rows.Scan(&a.ID, &a.AdvisoryID, &eco, &a.Package, &a.Version, &a.Repo, &decision, &a.Score, &a.Rationale,
			&a.Evidence, &conf, &a.InputsHash, &a.AssessedBy, &a.AssessedAt); err != nil {
			return nil, err
		}
		a.Ecosystem, a.Decision, a.Confidence = model.Ecosystem(eco), model.Decision(decision), model.Confidence(conf)
		out = append(out, a)
	}
	return out, rows.Err()
}
