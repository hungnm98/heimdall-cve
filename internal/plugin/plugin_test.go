package plugin

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type testCfg struct {
	BaseURL string        `mapstructure:"base_url"`
	Timeout time.Duration `mapstructure:"timeout"`
	Tags    []string      `mapstructure:"tags"`
}

func (c *testCfg) Validate() error {
	if c.BaseURL == "" {
		return errors.New("base_url required")
	}
	return nil
}

func TestDecode(t *testing.T) {
	var c testCfg
	err := Config{"base_url": "https://x", "timeout": "5s", "tags": "a,b"}.Decode(&c)
	if err != nil || c.Timeout != 5*time.Second || len(c.Tags) != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	if err := (Config{"base_ur": "typo"}).Decode(&testCfg{}); err == nil || !strings.Contains(err.Error(), "base_ur") {
		t.Fatalf("unknown key must fail, got %v", err)
	}
	if err := (Config{}).Decode(&testCfg{}); err == nil || !strings.Contains(err.Error(), "base_url required") {
		t.Fatalf("Validate must run, got %v", err)
	}
}
