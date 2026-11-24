package app

// Adapters compiled into the binary. Each package registers itself in init().
// To add a plugin: create its package, then add one blank import here.
import (
	_ "github.com/hungnm98/heimdall-cve/internal/jobs/inline"
	_ "github.com/hungnm98/heimdall-cve/internal/notify/slackwebhook"
	_ "github.com/hungnm98/heimdall-cve/internal/report/json"
	_ "github.com/hungnm98/heimdall-cve/internal/report/markdown"
	_ "github.com/hungnm98/heimdall-cve/internal/store/memstore"
	_ "github.com/hungnm98/heimdall-cve/internal/store/postgres"
)
