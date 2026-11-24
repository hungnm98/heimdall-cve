-- A job keeps the id of the run it produced even when that run is pruned by
-- retention, and the job record may be written before or independently of the
-- run row (store.Catalog does not require the run to exist: storetest.RunCatalog
-- saves a job with a run id that has no scan_runs row). The 0002 foreign key
-- made UpdateJob fail in that case, so it is dropped; run_id stays a plain
-- reference resolved by the reader.
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_run_id_fkey;
