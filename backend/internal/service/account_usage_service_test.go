package service

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
)

type accountUsageCodexProbeRepo struct {
	stubOpenAIAccountRepo
	updateExtraCh chan map[string]any
	rateLimitCh   chan time.Time
}

func (r *accountUsageCodexProbeRepo) UpdateExtra(_ context.Context, _ int64, updates map[string]any) error {
	if r.updateExtraCh != nil {
		copied := make(map[string]any, len(updates))
		for k, v := range updates {
			copied[k] = v
		}
		r.updateExtraCh <- copied
	}
	return nil
}

func (r *accountUsageCodexProbeRepo) SetRateLimited(_ context.Context, _ int64, resetAt time.Time) error {
	if r.rateLimitCh != nil {
		r.rateLimitCh <- resetAt
	}
	return nil
}

func TestShouldRefreshOpenAICodexSnapshot(t *testing.T) {
	t.Parallel()

	rateLimitedUntil := time.Now().Add(5 * time.Minute)
	now := time.Now()
	usage := &UsageInfo{
		FiveHour: &UsageProgress{Utilization: 0},
		SevenDay: &UsageProgress{Utilization: 0},
	}

	if !shouldRefreshOpenAICodexSnapshot(&Account{RateLimitResetAt: &rateLimitedUntil}, usage, now) {
		t.Fatal("expected rate-limited account to force codex snapshot refresh")
	}

	if shouldRefreshOpenAICodexSnapshot(&Account{}, usage, now) {
		t.Fatal("expected complete non-rate-limited usage to skip codex snapshot refresh")
	}

	if !shouldRefreshOpenAICodexSnapshot(&Account{}, &UsageInfo{FiveHour: nil, SevenDay: &UsageProgress{}}, now) {
		t.Fatal("expected missing 5h snapshot to require refresh")
	}

	staleAt := now.Add(-(openAIProbeCacheTTL + time.Minute)).Format(time.RFC3339)
	if !shouldRefreshOpenAICodexSnapshot(&Account{
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Extra: map[string]any{
			"openai_oauth_responses_websockets_v2_enabled": true,
			"codex_usage_updated_at":                       staleAt,
		},
	}, usage, now) {
		t.Fatal("expected stale ws snapshot to trigger refresh")
	}
}

func TestExtractOpenAICodexProbeUpdatesAccepts429WithCodexHeaders(t *testing.T) {
	t.Parallel()

	headers := make(http.Header)
	headers.Set("x-codex-primary-used-percent", "100")
	headers.Set("x-codex-primary-reset-after-seconds", "604800")
	headers.Set("x-codex-primary-window-minutes", "10080")
	headers.Set("x-codex-secondary-used-percent", "100")
	headers.Set("x-codex-secondary-reset-after-seconds", "18000")
	headers.Set("x-codex-secondary-window-minutes", "300")

	updates, err := extractOpenAICodexProbeUpdates(&http.Response{StatusCode: http.StatusTooManyRequests, Header: headers})
	if err != nil {
		t.Fatalf("extractOpenAICodexProbeUpdates() error = %v", err)
	}
	if len(updates) == 0 {
		t.Fatal("expected codex probe updates from 429 headers")
	}
	if got := updates["codex_5h_used_percent"]; got != 100.0 {
		t.Fatalf("codex_5h_used_percent = %v, want 100", got)
	}
	if got := updates["codex_7d_used_percent"]; got != 100.0 {
		t.Fatalf("codex_7d_used_percent = %v, want 100", got)
	}
}

func TestExtractOpenAICodexProbeSnapshotAccepts429WithResetAt(t *testing.T) {
	t.Parallel()

	headers := make(http.Header)
	headers.Set("x-codex-primary-used-percent", "100")
	headers.Set("x-codex-primary-reset-after-seconds", "604800")
	headers.Set("x-codex-primary-window-minutes", "10080")
	headers.Set("x-codex-secondary-used-percent", "100")
	headers.Set("x-codex-secondary-reset-after-seconds", "18000")
	headers.Set("x-codex-secondary-window-minutes", "300")

	updates, resetAt, err := extractOpenAICodexProbeSnapshot(&http.Response{StatusCode: http.StatusTooManyRequests, Header: headers})
	if err != nil {
		t.Fatalf("extractOpenAICodexProbeSnapshot() error = %v", err)
	}
	if len(updates) == 0 {
		t.Fatal("expected codex probe updates from 429 headers")
	}
	if resetAt == nil {
		t.Fatal("expected resetAt from exhausted codex headers")
	}
}

func TestAccountUsageService_PersistOpenAICodexProbeSnapshotSetsRateLimit(t *testing.T) {
	t.Parallel()

	repo := &accountUsageCodexProbeRepo{
		updateExtraCh: make(chan map[string]any, 1),
		rateLimitCh:   make(chan time.Time, 1),
	}
	svc := &AccountUsageService{accountRepo: repo}
	resetAt := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)

	svc.persistOpenAICodexProbeSnapshot(321, map[string]any{
		"codex_7d_used_percent": 100.0,
		"codex_7d_reset_at":     resetAt.Format(time.RFC3339),
	}, &resetAt)

	select {
	case updates := <-repo.updateExtraCh:
		if got := updates["codex_7d_used_percent"]; got != 100.0 {
			t.Fatalf("codex_7d_used_percent = %v, want 100", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting for codex probe extra persistence timed out")
	}

	select {
	case got := <-repo.rateLimitCh:
		if got.Before(resetAt.Add(-time.Second)) || got.After(resetAt.Add(time.Second)) {
			t.Fatalf("rate limit resetAt = %v, want around %v", got, resetAt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting for codex probe rate limit persistence timed out")
	}
}

func TestBuildCodexUsageProgressFromExtra_ZerosExpiredWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	t.Run("expired 5h window zeroes utilization", func(t *testing.T) {
		extra := map[string]any{
			"codex_5h_used_percent": 42.0,
			"codex_5h_reset_at":     "2026-03-16T10:00:00Z", // 2h ago
		}
		progress := buildCodexUsageProgressFromExtra(extra, "5h", now)
		if progress == nil {
			t.Fatal("expected non-nil progress")
		}
		if progress.Utilization != 0 {
			t.Fatalf("expected Utilization=0 for expired window, got %v", progress.Utilization)
		}
		if progress.RemainingSeconds != 0 {
			t.Fatalf("expected RemainingSeconds=0, got %v", progress.RemainingSeconds)
		}
	})

	t.Run("active 5h window keeps utilization", func(t *testing.T) {
		resetAt := now.Add(2 * time.Hour).Format(time.RFC3339)
		extra := map[string]any{
			"codex_5h_used_percent": 42.0,
			"codex_5h_reset_at":     resetAt,
		}
		progress := buildCodexUsageProgressFromExtra(extra, "5h", now)
		if progress == nil {
			t.Fatal("expected non-nil progress")
		}
		if progress.Utilization != 42.0 {
			t.Fatalf("expected Utilization=42, got %v", progress.Utilization)
		}
	})

	t.Run("expired 7d window zeroes utilization", func(t *testing.T) {
		extra := map[string]any{
			"codex_7d_used_percent": 88.0,
			"codex_7d_reset_at":     "2026-03-15T00:00:00Z", // yesterday
		}
		progress := buildCodexUsageProgressFromExtra(extra, "7d", now)
		if progress == nil {
			t.Fatal("expected non-nil progress")
		}
		if progress.Utilization != 0 {
			t.Fatalf("expected Utilization=0 for expired 7d window, got %v", progress.Utilization)
		}
	})
}

// ── Fix 1: GetPassiveUsage zeroes 7d utilization when the window has expired ──

type passiveUsageAccountRepo struct {
	stubOpenAIAccountRepo
	account *Account
}

func (r *passiveUsageAccountRepo) GetByID(_ context.Context, _ int64) (*Account, error) {
	if r.account == nil {
		return nil, errors.New("not found")
	}
	return r.account, nil
}

type stubWindowStatsRepo struct {
	UsageLogRepository
	startTimes []time.Time // records each startTime argument received
}

func (r *stubWindowStatsRepo) GetAccountWindowStats(_ context.Context, _ int64, startTime time.Time) (*usagestats.AccountStats, error) {
	r.startTimes = append(r.startTimes, startTime)
	return &usagestats.AccountStats{Requests: 10}, nil
}

func TestGetPassiveUsage_ExpiredSevenDayWindowZeroesUtilization(t *testing.T) {
	t.Parallel()

	expiredReset := time.Now().Add(-1 * time.Hour) // reset 1h ago → window expired

	account := &Account{
		ID:       1,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra: map[string]any{
			"passive_usage_7d_utilization": 0.07, // 7%
			"passive_usage_7d_reset":       float64(expiredReset.Unix()),
		},
	}

	svc := &AccountUsageService{
		accountRepo:  &passiveUsageAccountRepo{account: account},
		usageLogRepo: &stubWindowStatsRepo{},
		cache:        NewUsageCache(),
	}

	info, err := svc.GetPassiveUsage(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetPassiveUsage() error = %v", err)
	}
	if info.SevenDay == nil {
		t.Fatal("expected SevenDay to be non-nil")
	}
	if info.SevenDay.Utilization != 0 {
		t.Fatalf("expected Utilization=0 for expired 7d window, got %v", info.SevenDay.Utilization)
	}
	if info.SevenDay.RemainingSeconds != 0 {
		t.Fatalf("expected RemainingSeconds=0 for expired 7d window, got %v", info.SevenDay.RemainingSeconds)
	}
}

func TestGetPassiveUsage_ActiveSevenDayWindowPreservesUtilization(t *testing.T) {
	t.Parallel()

	futureReset := time.Now().Add(6*24*time.Hour + 8*time.Hour) // 6d 8h from now

	account := &Account{
		ID:       2,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra: map[string]any{
			"passive_usage_7d_utilization": 0.07,
			"passive_usage_7d_reset":       float64(futureReset.Unix()),
		},
	}

	svc := &AccountUsageService{
		accountRepo:  &passiveUsageAccountRepo{account: account},
		usageLogRepo: &stubWindowStatsRepo{},
		cache:        NewUsageCache(),
	}

	info, err := svc.GetPassiveUsage(context.Background(), 2)
	if err != nil {
		t.Fatalf("GetPassiveUsage() error = %v", err)
	}
	if info.SevenDay == nil {
		t.Fatal("expected SevenDay to be non-nil")
	}
	if diff := info.SevenDay.Utilization - 7.0; diff > 0.001 || diff < -0.001 {
		t.Fatalf("expected Utilization≈7, got %v", info.SevenDay.Utilization)
	}
	if info.SevenDay.RemainingSeconds <= 0 {
		t.Fatalf("expected positive RemainingSeconds, got %v", info.SevenDay.RemainingSeconds)
	}
}

// ── Fix 2: getOpenAIUsage uses actual quota window start time for stats queries ──

func TestGetOpenAIUsage_StatsStartTimeAlignedWithQuotaWindow(t *testing.T) {
	t.Parallel()

	now := time.Now()
	// 7d window started 16h ago (6d 8h remaining)
	sevenDayResetsAt := now.Add(6*24*time.Hour + 8*time.Hour)
	expectedSevenDayStart := sevenDayResetsAt.Add(-7 * 24 * time.Hour)

	// 5h window started 1.5h ago (3h 30m remaining)
	fiveHourResetsAt := now.Add(3*time.Hour + 30*time.Minute)
	expectedFiveHourStart := fiveHourResetsAt.Add(-5 * time.Hour)

	account := &Account{
		ID:       3,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Extra: map[string]any{
			"codex_5h_used_percent":  1.0,
			"codex_5h_reset_at":      fiveHourResetsAt.UTC().Format(time.RFC3339),
			"codex_7d_used_percent":  7.0,
			"codex_7d_reset_at":      sevenDayResetsAt.UTC().Format(time.RFC3339),
			"codex_usage_updated_at": now.UTC().Format(time.RFC3339),
		},
	}

	statsRepo := &stubWindowStatsRepo{}
	svc := &AccountUsageService{
		accountRepo:  &passiveUsageAccountRepo{account: account},
		usageLogRepo: statsRepo,
		cache:        NewUsageCache(),
	}

	_, err := svc.getOpenAIUsage(context.Background(), account)
	if err != nil {
		t.Fatalf("getOpenAIUsage() error = %v", err)
	}

	if len(statsRepo.startTimes) != 2 {
		t.Fatalf("expected 2 GetAccountWindowStats calls (5h + 7d), got %d", len(statsRepo.startTimes))
	}

	gotFiveHourStart := statsRepo.startTimes[0]
	if diff := gotFiveHourStart.Sub(expectedFiveHourStart).Abs(); diff > time.Second {
		t.Fatalf("5h stats startTime = %v, want ~%v (diff %v)", gotFiveHourStart, expectedFiveHourStart, diff)
	}

	gotSevenDayStart := statsRepo.startTimes[1]
	if diff := gotSevenDayStart.Sub(expectedSevenDayStart).Abs(); diff > time.Second {
		t.Fatalf("7d stats startTime = %v, want ~%v (diff %v)", gotSevenDayStart, expectedSevenDayStart, diff)
	}
}

func TestGetOpenAIUsage_StatsStartTimeFallsBackToRollingWindowWhenNoResetsAt(t *testing.T) {
	t.Parallel()

	now := time.Now()
	account := &Account{
		ID:       4,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{}, // no codex data → no ResetsAt
	}

	statsRepo := &stubWindowStatsRepo{}
	svc := &AccountUsageService{
		accountRepo:  &passiveUsageAccountRepo{account: account},
		usageLogRepo: statsRepo,
		cache:        NewUsageCache(),
	}

	_, err := svc.getOpenAIUsage(context.Background(), account)
	if err != nil {
		t.Fatalf("getOpenAIUsage() error = %v", err)
	}

	// With no ResetsAt, stats should fall back to rolling windows
	if len(statsRepo.startTimes) != 2 {
		t.Fatalf("expected 2 GetAccountWindowStats calls, got %d", len(statsRepo.startTimes))
	}

	expectedFiveHourStart := now.Add(-5 * time.Hour)
	if diff := statsRepo.startTimes[0].Sub(expectedFiveHourStart).Abs(); diff > 2*time.Second {
		t.Fatalf("5h fallback startTime off by %v", diff)
	}

	expectedSevenDayStart := now.Add(-7 * 24 * time.Hour)
	if diff := statsRepo.startTimes[1].Sub(expectedSevenDayStart).Abs(); diff > 2*time.Second {
		t.Fatalf("7d fallback startTime off by %v", diff)
	}
}
