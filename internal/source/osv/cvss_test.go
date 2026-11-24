package osv

import (
	"fmt"
	"testing"
)

func TestCVSS3BaseScore(t *testing.T) {
	// Scores from the FIRST CVSS v3.1 calculator / NVD.
	for vec, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N": 5.4,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H": 5.9,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H": 7.4,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H": 9.1,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
		// temporal metrics are ignored
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C": 9.8,
	} {
		got, err := CVSS3BaseScore(vec)
		if err != nil || got != want {
			t.Errorf("CVSS3BaseScore(%s) = %v, %v; want %v", vec, got, err, want)
		}
	}
	for _, bad := range []string{
		"",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H",
		"CVSS:3.1/AVN",
	} {
		if _, err := CVSS3BaseScore(bad); err == nil {
			t.Errorf("CVSS3BaseScore(%q) accepted an invalid vector", bad)
		}
	}
}

func TestRoundup(t *testing.T) {
	for in, want := range map[float64]float64{4.0: 4.0, 4.02: 4.1, 4.00000001: 4.0, 9.71: 9.8} {
		if got := roundup(in); got != want {
			t.Errorf("roundup(%v) = %v; want %v", in, got, want)
		}
	}
}

func TestEventsToRanges(t *testing.T) {
	got := eventsToRanges([]osvEvent{
		{Introduced: "0"}, {Fixed: "1.0.0"},
		{Introduced: "2.0.0"}, {LastAffected: "2.3.0"},
		{Introduced: "3.0.0"},
	})
	want := "[{0 1.0.0 } {2.0.0  2.3.0} {3.0.0  }]"
	if s := fmt.Sprint(got); s != want {
		t.Errorf("ranges = %s; want %s", s, want)
	}
}
