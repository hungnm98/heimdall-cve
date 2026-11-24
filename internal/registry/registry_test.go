package registry

import (
	"errors"
	"testing"
)

func TestRegistry(t *testing.T) {
	r := New[func() int]("test-kind")
	r.Register("b", func() int { return 2 })
	r.Register("a", func() int { return 1 })

	f, err := r.Get("a")
	if err != nil || f() != 1 {
		t.Fatalf("Get(a) err = %v", err)
	}
	if _, err := r.Get("zzz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(zzz) err = %v, want ErrNotFound", err)
	}
	if got := r.Names(); len(got) != 2 || got[0] != "a" {
		t.Fatalf("Names() = %v", got)
	}
	if got := Catalog()["test-kind"]; len(got) != 2 {
		t.Fatalf("Catalog() = %v", got)
	}
	assertPanics(t, func() { r.Register("a", nil) })
	assertPanics(t, func() { r.Register("", nil) })
	assertPanics(t, func() { New[int]("test-kind") })
}

func assertPanics(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	f()
}
