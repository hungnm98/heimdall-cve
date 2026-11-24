-- Web app catalog: auth profiles, sealed secrets, targets, cached repo list,
-- scan jobs with progress events, audit log. Behaviour: storetest.RunCatalog.

CREATE TABLE secrets (
    id          BIGSERIAL   PRIMARY KEY,
    kind        text        NOT NULL,
    kek_id      text        NOT NULL,
    wrapped_dek bytea       NOT NULL,
    ciphertext  bytea       NOT NULL,
    fingerprint text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    rotated_at  timestamptz
);
-- KEK rotation walks secrets still wrapped by an old key.
CREATE INDEX secrets_kek_idx ON secrets (kek_id);

CREATE TABLE auth_profiles (
    id                 BIGSERIAL   PRIMARY KEY,
    name               text        NOT NULL UNIQUE,
    type               text        NOT NULL,
    options            jsonb       NOT NULL DEFAULT '{}', -- never secret values
    secret_id          bigint      REFERENCES secrets (id) ON DELETE RESTRICT,
    secret_fingerprint text        NOT NULL DEFAULT '',
    origin             text        NOT NULL CHECK (origin IN ('config', 'ui')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE targets (
    id          BIGSERIAL   PRIMARY KEY,
    kind        text        NOT NULL CHECK (kind IN ('org', 'user', 'repo')),
    provider    text        NOT NULL,
    base_url    text        NOT NULL DEFAULT '',
    owner       text        NOT NULL,
    name        text        NOT NULL DEFAULT '', -- repo name for kind=repo
    branch      text        NOT NULL DEFAULT '',
    -- Profiles are referenced by name (like the config file); renames cascade.
    auth        text        NOT NULL REFERENCES auth_profiles (name) ON UPDATE CASCADE ON DELETE RESTRICT,
    list_auth   text        NOT NULL REFERENCES auth_profiles (name) ON UPDATE CASCADE ON DELETE RESTRICT,
    repos       text[]      NOT NULL DEFAULT '{}',
    filter      jsonb       NOT NULL DEFAULT '{}',
    schedule    text        NOT NULL DEFAULT '', -- cron; '' = manual only
    enabled     boolean     NOT NULL DEFAULT true,
    origin      text        NOT NULL CHECK (origin IN ('config', 'ui')),
    next_run_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
-- Scheduler: due enabled targets, oldest first.
CREATE INDEX targets_due_idx ON targets (next_run_at, id) WHERE enabled;

-- Cached repo listing (UI "Repos" page, incremental scans).
CREATE TABLE repos (
    full_name       text        PRIMARY KEY, -- owner/name
    target_id       bigint      NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    data            jsonb       NOT NULL,    -- model.Repo
    last_listed_at  timestamptz NOT NULL,
    last_head_sha   text        NOT NULL DEFAULT '',
    last_scanned_at timestamptz
);
CREATE INDEX repos_target_idx ON repos (target_id, full_name);

CREATE TABLE scan_jobs (
    id           BIGSERIAL   PRIMARY KEY,
    target_id    bigint      REFERENCES targets (id) ON DELETE SET NULL,
    repo         text        NOT NULL DEFAULT '',
    branch       text        NOT NULL DEFAULT '',
    auth_profile text        NOT NULL DEFAULT '',
    trigger      text        NOT NULL,
    status       text        NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    run_id       bigint      REFERENCES scan_runs (id) ON DELETE SET NULL,
    attempts     int         NOT NULL DEFAULT 0,
    requested_by text        NOT NULL DEFAULT '',
    error        text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz
);
-- At most one active job per scope: "scan now" twice queues one job.
CREATE UNIQUE INDEX scan_jobs_active_scope_idx ON scan_jobs (COALESCE(target_id, 0), repo)
    WHERE status IN ('queued', 'running');
CREATE INDEX scan_jobs_status_idx ON scan_jobs (status, id DESC);
CREATE INDEX scan_jobs_target_idx ON scan_jobs (target_id, id DESC);

CREATE TABLE job_events (
    id      BIGSERIAL   PRIMARY KEY,
    job_id  bigint      NOT NULL REFERENCES scan_jobs (id) ON DELETE CASCADE,
    at      timestamptz NOT NULL DEFAULT now(),
    level   text        NOT NULL DEFAULT 'info',
    repo    text        NOT NULL DEFAULT '',
    message text        NOT NULL
);
CREATE INDEX job_events_job_idx ON job_events (job_id, id);

CREATE TABLE audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor       text        NOT NULL,
    action      text        NOT NULL,
    object_type text        NOT NULL DEFAULT '',
    object_id   text        NOT NULL DEFAULT '',
    details     jsonb       NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);

-- Suppressions: always with a reason and an expiry.
CREATE TABLE suppressions (
    finding_id text        PRIMARY KEY REFERENCES findings (id) ON DELETE CASCADE,
    reason     text        NOT NULL CHECK (length(btrim(reason)) > 0),
    expires_at timestamptz NOT NULL,
    actor      text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX suppressions_expires_idx ON suppressions (expires_at);

-- Per-run summary for dashboard trends.
ALTER TABLE scan_runs ADD COLUMN stats jsonb NOT NULL DEFAULT '{}';
