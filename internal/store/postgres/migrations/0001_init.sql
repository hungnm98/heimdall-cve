-- Heimdall initial schema (PostgreSQL 14+).
-- Hot query columns are real columns with indexes; the full record is kept in
-- `data` (jsonb) so new model fields need no migration.

CREATE TABLE scan_runs (
    id            BIGSERIAL PRIMARY KEY,
    started_at    timestamptz NOT NULL,
    finished_at   timestamptz,
    status        text        NOT NULL,
    targets       text[]      NOT NULL DEFAULT '{}',
    repos_scanned text[]      NOT NULL DEFAULT '{}',
    repos_failed  text[]      NOT NULL DEFAULT '{}',
    sources       jsonb       NOT NULL DEFAULT '[]',
    error         text        NOT NULL DEFAULT ''
);
-- LatestRun: newest finished run.
CREATE INDEX scan_runs_finished_idx ON scan_runs (id DESC) WHERE status <> 'running';

CREATE TABLE findings (
    id              text        PRIMARY KEY,
    kind            text        NOT NULL,
    provider        text        NOT NULL,
    repo            text        NOT NULL,
    manifest_path   text        NOT NULL,
    ecosystem       text        NOT NULL,
    package_name    text        NOT NULL,
    package_version text        NOT NULL,
    purl            text        NOT NULL,
    advisory_id     text        NOT NULL,
    severity        text        NOT NULL,
    severity_rank   smallint    NOT NULL,
    in_kev          boolean     NOT NULL DEFAULT false,
    status          text        NOT NULL,
    first_seen      timestamptz NOT NULL,
    last_seen       timestamptz NOT NULL,
    data            jsonb       NOT NULL
);
-- RecordFindings closes open findings per scanned repo; get_findings(repo=...).
CREATE INDEX findings_repo_status_idx   ON findings (repo, status);
-- Dashboards / digests: open findings, worst first.
CREATE INDEX findings_status_rank_idx   ON findings (status, severity_rank DESC, repo, id);
CREATE INDEX findings_first_seen_idx    ON findings (first_seen);
CREATE INDEX findings_kev_idx           ON findings (repo) WHERE in_kev;
-- "Which repos use package X?" (MCP get_inventory / agent analysis).
CREATE INDEX findings_package_idx       ON findings (ecosystem, package_name);
CREATE INDEX findings_advisory_idx      ON findings (advisory_id);

-- Findings each run recorded (non-suppressed), for diff between any two runs.
-- Grows by (#open findings × #runs): prune old runs with a retention job.
CREATE TABLE run_findings (
    run_id     bigint NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    finding_id text   NOT NULL,
    PRIMARY KEY (run_id, finding_id)
);

-- Repos each run actually scanned (scope for "fixed").
CREATE TABLE run_repos (
    run_id bigint NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    repo   text   NOT NULL,
    PRIMARY KEY (run_id, repo)
);

-- Incremental scans: last scanned HEAD per repo/ref.
CREATE TABLE repo_states (
    repo       text        NOT NULL,
    ref        text        NOT NULL,
    head_sha   text        NOT NULL,
    scanned_at timestamptz NOT NULL,
    PRIMARY KEY (repo, ref)
);

-- Notification idempotency keys.
CREATE TABLE notifications (
    key         text        PRIMARY KEY,
    notified_at timestamptz NOT NULL
);
