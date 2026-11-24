package mcpserver

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/store/memstore"
)

func TestStreamableHTTP(t *testing.T) {
	srv := New(service.New(service.Deps{Store: memstore.New()}), Options{})
	hs := httptest.NewServer(srv.HTTPHandler())
	defer hs.Close()
	ctx := context.Background()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "http-agent", Version: "1"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: hs.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_runs"})
	if err != nil || res.IsError {
		t.Fatalf("list_runs over HTTP: %v %+v", err, res)
	}
}
