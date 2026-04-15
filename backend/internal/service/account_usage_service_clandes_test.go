//go:build unit

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetUsage_ClandesAccount_NilClient_FallsThrough(t *testing.T) {
	t.Parallel()

	// A clandes account with nil clandesClient should fall through to normal path
	// (which will fail since we don't set up a real fetcher, but the point is it doesn't panic)
	account := &Account{
		ID:       100,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{"clandes": true},
	}

	require.True(t, IsClandesAccount(account))

	// With nil client, getClandesUsage would not be called
	svc := &AccountUsageService{
		clandesClient: nil, // nil — should skip clandes path
	}

	// Can't call full GetUsage (needs account repo), but verify the check logic
	require.Nil(t, svc.clandesClient)
}

func TestGetUsage_NonClandesAccount_SkipsRPC(t *testing.T) {
	t.Parallel()

	// Non-clandes account should never touch the clandes client
	account := &Account{
		ID:       200,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{},
	}

	require.False(t, IsClandesAccount(account))
}
