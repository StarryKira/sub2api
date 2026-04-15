//go:build unit

package service

import (
	"testing"
	"time"

	capnp "capnproto.org/go/capnp/v3"
	"github.com/stretchr/testify/require"

	proto "github.com/Wei-Shaw/sub2api/internal/pkg/clandes/proto"
)

func TestOAuthLoginResult_Fields(t *testing.T) {
	t.Parallel()

	result := &OAuthLoginResult{
		AccessToken:    "at-123",
		RefreshToken:   "rt-456",
		ExpiresIn:      3600,
		Email:          "user@example.com",
		OrganizationID: "org-789",
	}

	require.Equal(t, "at-123", result.AccessToken)
	require.Equal(t, "rt-456", result.RefreshToken)
	require.Equal(t, uint64(3600), result.ExpiresIn)
	require.Equal(t, "user@example.com", result.Email)
	require.Equal(t, "org-789", result.OrganizationID)
}

func TestUsagePeriodToProgress(t *testing.T) {
	t.Parallel()

	// Build a UsagePeriod via capnp
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	require.NoError(t, err)
	defer msg.Release()

	period, err := proto.NewRootUsagePeriod(seg)
	require.NoError(t, err)
	period.SetUtilization(42.5)

	futureTime := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, period.SetResetsAt(futureTime.Format(time.RFC3339)))

	prog := usagePeriodToProgress(period)
	require.InDelta(t, 42.5, prog.Utilization, 0.001)
	require.NotNil(t, prog.ResetsAt)
	require.Equal(t, futureTime, prog.ResetsAt.UTC().Truncate(time.Second))
	require.True(t, prog.RemainingSeconds > 0)
}

func TestUsagePeriodToProgress_EmptyResetsAt(t *testing.T) {
	t.Parallel()

	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	require.NoError(t, err)
	defer msg.Release()

	period, err := proto.NewRootUsagePeriod(seg)
	require.NoError(t, err)
	period.SetUtilization(75.0)
	// Don't set ResetsAt

	prog := usagePeriodToProgress(period)
	require.InDelta(t, 75.0, prog.Utilization, 0.001)
	require.Nil(t, prog.ResetsAt)
	require.Equal(t, 0, prog.RemainingSeconds)
}

func TestBuildClandesUsageInfo(t *testing.T) {
	t.Parallel()

	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	require.NoError(t, err)
	defer msg.Release()

	res, err := proto.NewRootClaudeQueryService_getUsage_Results(seg)
	require.NoError(t, err)
	res.SetSuccess(true)

	// Set 5-hour
	fh, err := res.NewFiveHour()
	require.NoError(t, err)
	fh.SetUtilization(30.0)
	futureTime := time.Now().Add(3 * time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, fh.SetResetsAt(futureTime.Format(time.RFC3339)))

	// Set 7-day
	sd, err := res.NewSevenDay()
	require.NoError(t, err)
	sd.SetUtilization(60.0)
	futureTime2 := time.Now().Add(5 * 24 * time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, sd.SetResetsAt(futureTime2.Format(time.RFC3339)))

	info, err := buildClandesUsageInfo(res)
	require.NoError(t, err)
	require.Equal(t, "active", info.Source)
	require.NotNil(t, info.UpdatedAt)

	require.NotNil(t, info.FiveHour)
	require.InDelta(t, 30.0, info.FiveHour.Utilization, 0.001)
	require.NotNil(t, info.FiveHour.ResetsAt)

	require.NotNil(t, info.SevenDay)
	require.InDelta(t, 60.0, info.SevenDay.Utilization, 0.001)

	// SevenDaySonnet not set
	require.Nil(t, info.SevenDaySonnet)
}

func TestClandesStatus_DisabledWhenNilClient(t *testing.T) {
	t.Parallel()

	// Verify that when the handler gets a nil client, it should return disabled status.
	// This tests the data structure; the nil-check behavior is tested in handler tests.
	status := ClandesStatus{
		Enabled:   false,
		Connected: false,
		Addr:      "",
	}
	require.False(t, status.Enabled)
	require.False(t, status.Connected)
	require.Empty(t, status.Addr)
}
