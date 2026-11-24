package osv

import "sync"

// inflight collapses concurrent calls with the same key into one (a minimal
// singleflight). Waiters share the leader's result, including its error.
type inflight struct {
	mu    sync.Mutex
	calls map[string]*call
	dups  int // number of calls that joined an in-flight one (for tests)
}

type call struct {
	done chan struct{}
	val  []byte
	err  error
}

func (g *inflight) do(key string, fn func() ([]byte, error)) ([]byte, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = map[string]*call{}
	}
	if c, ok := g.calls[key]; ok {
		g.dups++
		g.mu.Unlock()
		<-c.done
		return c.val, c.err
	}
	c := &call{done: make(chan struct{})}
	g.calls[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	close(c.done)
	return c.val, c.err
}
