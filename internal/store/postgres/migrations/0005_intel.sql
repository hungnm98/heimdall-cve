-- Intel: dependency inventory, agent-submitted advisories, library analyses.
-- Text keys use COLLATE "C" so ordering is byte-wise (matches the Go
-- reference store) whatever the database's default collation is.

-- One row per dependency per manifest, as last scanned. A scan replaces all
-- rows of a repo (DELETE + COPY in one transaction).
CREATE TABLE inventory (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo          text        COLLATE "C" NOT NULL,
    manifest_path text        COLLATE "C" NOT NULL,
    ecosystem     text        COLLATE "C" NOT NULL,
    name          text        COLLATE "C" NOT NULL,
    version       text        COLLATE "C" NOT NULL,
    purl          text        NOT NULL,
    direct        boolean     NOT NULL,
    scope         text        NOT NULL,
    private       boolean     NOT NULL,
    unresolvable  text        NOT NULL,
    scanned_at    timestamptz NOT NULL
);
-- ReplaceInventory's delete and ListInventory(repo=...) in output order.
CREATE INDEX inventory_repo_idx ON inventory (repo, manifest_path, ecosystem, name, version);
-- "Which repos use package X?" (ListInventory(ecosystem, name)).
CREATE INDEX inventory_package_idx ON inventory (ecosystem, name);
-- PackageUsage: only public, resolvable rows; index-only scan per library.
CREATE INDEX inventory_usage_idx ON inventory (ecosystem, name, version, repo) INCLUDE (direct)
    WHERE NOT private AND unresolvable = '';

CREATE TABLE agent_advisories (
    id           text        COLLATE "C" PRIMARY KEY,
    advisory     jsonb       NOT NULL,
    evidence     text[]      NOT NULL DEFAULT '{}',
    confidence   text        NOT NULL,
    submitted_by text        NOT NULL,
    submitted_at timestamptz NOT NULL
);

-- Append-only history of library analyses.
CREATE TABLE library_analyses (
    id                  bigserial   PRIMARY KEY,
    ecosystem           text        COLLATE "C" NOT NULL,
    name                text        COLLATE "C" NOT NULL,
    version             text        NOT NULL,
    verdict             text        NOT NULL,
    summary             text        NOT NULL,
    evidence            text[]      NOT NULL DEFAULT '{}',
    recommended_version text        NOT NULL,
    confidence          text        NOT NULL,
    agent               text        NOT NULL,
    analyzed_at         timestamptz NOT NULL
);
-- LatestAnalyses (DISTINCT ON) and AnalysisHistory (newest first).
CREATE INDEX library_analyses_lib_idx ON library_analyses (ecosystem, name, id DESC);
