-- Multi-branch scans and commit snapshots.

-- Findings on extra branches; '' = the repo's default branch (IDs of
-- default-branch findings are unchanged).
ALTER TABLE findings ADD COLUMN branch text COLLATE "C" NOT NULL DEFAULT '';
CREATE INDEX findings_repo_branch_idx ON findings (repo, branch) WHERE branch <> '';

-- Targets: extra branches (names or globs), a cap per repo, and a cheap
-- poll that only rescans repos whose commit moved.
ALTER TABLE targets
    ADD COLUMN branches     text[]      NOT NULL DEFAULT '{}',
    ADD COLUMN max_branches integer     NOT NULL DEFAULT 0,
    ADD COLUMN poll         text        NOT NULL DEFAULT '',
    ADD COLUMN next_poll_at timestamptz;
CREATE INDEX targets_poll_idx ON targets (next_poll_at, id) WHERE enabled AND next_poll_at IS NOT NULL;

-- Parsed dependency graphs per commit: an unchanged commit (on any branch)
-- is not read and parsed again. fingerprint covers parser and scan settings.
CREATE TABLE repo_snapshots (
    repo        text        COLLATE "C" NOT NULL,
    sha         text        COLLATE "C" NOT NULL,
    fingerprint text        COLLATE "C" NOT NULL,
    data        bytea       NOT NULL, -- gzip JSON
    created_at  timestamptz NOT NULL,
    used_at     timestamptz NOT NULL,
    PRIMARY KEY (repo, sha, fingerprint)
);
-- Pruning of snapshots unused for a while.
CREATE INDEX repo_snapshots_used_idx ON repo_snapshots (used_at);
