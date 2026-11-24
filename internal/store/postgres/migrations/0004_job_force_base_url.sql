-- Jobs carry "force rescan" and, for ad-hoc repos on GitHub Enterprise, the API base URL.
ALTER TABLE scan_jobs ADD COLUMN force boolean NOT NULL DEFAULT false;
ALTER TABLE scan_jobs ADD COLUMN base_url text NOT NULL DEFAULT '';
