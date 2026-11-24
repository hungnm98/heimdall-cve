package memstore

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/store/storetest"
)

func TestContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return New() })
}

func TestCatalogContract(t *testing.T) {
	storetest.RunCatalog(t, func(*testing.T) store.Store { return New() })
}
