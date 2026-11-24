-- Append-only history of agent finding assessments (triage decisions).
-- Key: (advisory_id, ecosystem, package, version, repo); repo '' = every repo.
-- Text keys use COLLATE "C" like 0005_intel.
CREATE TABLE finding_assessments (
    id          bigserial   PRIMARY KEY,
    advisory_id text        COLLATE "C" NOT NULL,
    ecosystem   text        COLLATE "C" NOT NULL,
    package     text        COLLATE "C" NOT NULL,
    version     text        COLLATE "C" NOT NULL,
    repo        text        COLLATE "C" NOT NULL,
    decision    text        NOT NULL,
    score       double precision NOT NULL,
    rationale   text        NOT NULL,
    evidence    text[]      NOT NULL DEFAULT '{}',
    confidence  text        NOT NULL,
    inputs_hash text        NOT NULL,
    assessed_by text        NOT NULL,
    assessed_at timestamptz NOT NULL
);
-- LatestAssessments (newest per key) and AssessmentHistory (newest first).
CREATE INDEX finding_assessments_key_idx ON finding_assessments (advisory_id, ecosystem, package, version, repo, id DESC);
