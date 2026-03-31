package claude

import (
	"testing"
)

func TestSelectProfileForAccount_Deterministic(t *testing.T) {
	// Same accountID always produces same result
	r1 := SelectProfileForAccount(42, -1)
	r2 := SelectProfileForAccount(42, -1)

	if r1.UserAgent != r2.UserAgent {
		t.Errorf("UserAgent not deterministic: %q != %q", r1.UserAgent, r2.UserAgent)
	}
	if r1.Profile.OS != r2.Profile.OS {
		t.Errorf("OS not deterministic: %q != %q", r1.Profile.OS, r2.Profile.OS)
	}
	if r1.CLIVersion != r2.CLIVersion {
		t.Errorf("CLIVersion not deterministic: %q != %q", r1.CLIVersion, r2.CLIVersion)
	}
	if r1.PackageVersion != r2.PackageVersion {
		t.Errorf("PackageVersion not deterministic: %q != %q", r1.PackageVersion, r2.PackageVersion)
	}
	if r1.RuntimeVersion != r2.RuntimeVersion {
		t.Errorf("RuntimeVersion not deterministic: %q != %q", r1.RuntimeVersion, r2.RuntimeVersion)
	}
}

func TestSelectProfileForAccount_Diverse(t *testing.T) {
	// Different accountIDs should produce at least 2 different OS values across 100 accounts
	osSet := make(map[string]struct{})
	for i := int64(1); i <= 100; i++ {
		sel := SelectProfileForAccount(i, -1)
		osSet[sel.Profile.OS] = struct{}{}
	}

	if len(osSet) < 2 {
		t.Errorf("expected at least 2 different OS values across 100 accounts, got %d: %v", len(osSet), osSet)
	}
}

func TestSelectProfileForAccount_LockedIndex(t *testing.T) {
	// When lockedIndex is provided, profile selection should use that index
	sel0 := SelectProfileForAccount(999, 0)
	sel4 := SelectProfileForAccount(999, 4)

	if sel0.Profile.OS != RealisticProfiles[0].OS {
		t.Errorf("lockedIndex=0 should use profile[0], got OS=%q, want %q", sel0.Profile.OS, RealisticProfiles[0].OS)
	}
	if sel4.Profile.OS != RealisticProfiles[4].OS {
		t.Errorf("lockedIndex=4 should use profile[4], got OS=%q, want %q", sel4.Profile.OS, RealisticProfiles[4].OS)
	}
}

func TestSelectProfileForAccount_ValidOutput(t *testing.T) {
	for i := int64(0); i < 50; i++ {
		sel := SelectProfileForAccount(i, -1)

		if sel.UserAgent == "" {
			t.Errorf("account %d: empty UserAgent", i)
		}
		if sel.CLIVersion == "" {
			t.Errorf("account %d: empty CLIVersion", i)
		}
		if sel.PackageVersion == "" {
			t.Errorf("account %d: empty PackageVersion", i)
		}
		if sel.RuntimeVersion == "" {
			t.Errorf("account %d: empty RuntimeVersion", i)
		}
		if sel.Profile.OS == "" {
			t.Errorf("account %d: empty OS", i)
		}
		if sel.Profile.Arch == "" {
			t.Errorf("account %d: empty Arch", i)
		}
	}
}
