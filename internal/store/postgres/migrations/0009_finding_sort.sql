-- Sortable finding lists (GET /findings?sort=...&order=...).
-- priority and sort_name were only inside `data`; they become columns so the
-- keyset pagination of every order can use an index.
--   priority  = Finding.Priority (0-100)
--   sort_name = store.FindingSortName: lower(package name, else runtime name,
--               else advisory id). COLLATE "C": byte-wise, like the Go
--               reference store.
ALTER TABLE findings
    ADD COLUMN priority  double precision NOT NULL DEFAULT 0,
    ADD COLUMN sort_name text COLLATE "C" NOT NULL DEFAULT '';

UPDATE findings SET
    priority  = COALESCE((data->>'Priority')::double precision, 0),
    sort_name = lower(COALESCE(NULLIF(package_name, ''), NULLIF(data#>>'{Runtime,Runtime,Name}', ''), advisory_id));

-- One index per order, led by status (lists are almost always status = 'open').
-- Each order is (key, id) in one direction, so a backward scan serves the
-- other direction. severity is served by findings_status_rank_idx (0001).
CREATE INDEX findings_status_priority_idx   ON findings (status, priority, id);
CREATE INDEX findings_status_sort_name_idx  ON findings (status, sort_name, id);
CREATE INDEX findings_status_first_seen_idx ON findings (status, first_seen, id);
CREATE INDEX findings_status_repo_c_idx     ON findings (status, repo COLLATE "C", id);
