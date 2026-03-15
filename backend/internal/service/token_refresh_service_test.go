//go:build unit

package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type tokenRefreshAccountRepo struct {
	mockAccountRepoForGemini
	updateCalls    int
	setErrorCalls  int
	clearTempCalls int
	getByIDCalls   int
	lastAccount    *Account
	updateErr      error
}

func (r *tokenRefreshAccountRepo) GetByID(ctx context.Context, id int64) (*Account, error) {
	r.getByIDCalls++
	return r.mockAccountRepoForGemini.GetByID(ctx, id)
}

func (r *tokenRefreshAccountRepo) Update(ctx context.Context, account *Account) error {
	r.updateCalls++
	r.lastAccount = account
	return r.updateErr
}

func (r *tokenRefreshAccountRepo) SetError(ctx context.Context, id int64, errorMsg string) error {
	r.setErrorCalls++
	return nil
}

func (r *tokenRefreshAccountRepo) ClearTempUnschedulable(ctx context.Context, id int64) error {
	r.clearTempCalls++
	return nil
}

// lockableRefresherStub implements TokenRefresher + LockableRefresher for distributed lock tests.
type lockableRefresherStub struct {
	creds          map[string]any
	refreshErr     error
	lockKey        string
	needsRefreshFn func(account *Account) bool // nil → always true
	refreshCalls   int
}

func (r *lockableRefresherStub) CanRefresh(*Account) bool { return true }

func (r *lockableRefresherStub) NeedsRefresh(account *Account, _ time.Duration) bool {
	if r.needsRefreshFn != nil {
		return r.needsRefreshFn(account)
	}
	return true
}

func (r *lockableRefresherStub) RefreshLockKey(*Account) string { return r.lockKey }

func (r *lockableRefresherStub) Refresh(_ context.Context, _ *Account) (map[string]any, error) {
	r.refreshCalls++
	if r.refreshErr != nil {
		return nil, r.refreshErr
	}
	return r.creds, nil
}

// refreshLockerStub implements RefreshLocker for unit tests.
type refreshLockerStub struct {
	locked       bool
	acquireErr   error
	acquireCalls int
	releaseCalls int
}

func (s *refreshLockerStub) AcquireRefreshLock(_ context.Context, _ string, _ time.Duration) (bool, error) {
	s.acquireCalls++
	return s.locked, s.acquireErr
}

func (s *refreshLockerStub) ReleaseRefreshLock(_ context.Context, _ string) error {
	s.releaseCalls++
	return nil
}

type tokenCacheInvalidatorStub struct {
	calls int
	err   error
}

func (s *tokenCacheInvalidatorStub) InvalidateToken(ctx context.Context, account *Account) error {
	s.calls++
	return s.err
}

type tempUnschedCacheStub struct {
	deleteCalls int
}

func (s *tempUnschedCacheStub) SetTempUnsched(ctx context.Context, accountID int64, state *TempUnschedState) error {
	return nil
}

func (s *tempUnschedCacheStub) GetTempUnsched(ctx context.Context, accountID int64) (*TempUnschedState, error) {
	return nil, nil
}

func (s *tempUnschedCacheStub) DeleteTempUnsched(ctx context.Context, accountID int64) error {
	s.deleteCalls++
	return nil
}

type tokenRefresherStub struct {
	credentials map[string]any
	err         error
}

func (r *tokenRefresherStub) CanRefresh(account *Account) bool {
	return true
}

func (r *tokenRefresherStub) NeedsRefresh(account *Account, refreshWindowDuration time.Duration) bool {
	return true
}

func (r *tokenRefresherStub) Refresh(ctx context.Context, account *Account) (map[string]any, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.credentials, nil
}

func TestTokenRefreshService_RefreshWithRetry_InvalidatesCache(t *testing.T) {
	repo := &tokenRefreshAccountRepo{}
	invalidator := &tokenCacheInvalidatorStub{}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          1,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, nil)
	account := &Account{
		ID:       5,
		Platform: PlatformGemini,
		Type:     AccountTypeOAuth,
	}
	refresher := &tokenRefresherStub{
		credentials: map[string]any{
			"access_token": "new-token",
		},
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.NoError(t, err)
	require.Equal(t, 1, repo.updateCalls)
	require.Equal(t, 1, invalidator.calls)
	require.Equal(t, "new-token", account.GetCredential("access_token"))
}

func TestTokenRefreshService_RefreshWithRetry_InvalidatorErrorIgnored(t *testing.T) {
	repo := &tokenRefreshAccountRepo{}
	invalidator := &tokenCacheInvalidatorStub{err: errors.New("invalidate failed")}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          1,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, nil)
	account := &Account{
		ID:       6,
		Platform: PlatformGemini,
		Type:     AccountTypeOAuth,
	}
	refresher := &tokenRefresherStub{
		credentials: map[string]any{
			"access_token": "token",
		},
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.NoError(t, err)
	require.Equal(t, 1, repo.updateCalls)
	require.Equal(t, 1, invalidator.calls)
}

func TestTokenRefreshService_RefreshWithRetry_NilInvalidator(t *testing.T) {
	repo := &tokenRefreshAccountRepo{}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          1,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, nil, nil, cfg, nil)
	account := &Account{
		ID:       7,
		Platform: PlatformGemini,
		Type:     AccountTypeOAuth,
	}
	refresher := &tokenRefresherStub{
		credentials: map[string]any{
			"access_token": "token",
		},
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.NoError(t, err)
	require.Equal(t, 1, repo.updateCalls)
}

// TestTokenRefreshService_RefreshWithRetry_Antigravity 测试 Antigravity 平台的缓存失效
func TestTokenRefreshService_RefreshWithRetry_Antigravity(t *testing.T) {
	repo := &tokenRefreshAccountRepo{}
	invalidator := &tokenCacheInvalidatorStub{}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          1,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, nil)
	account := &Account{
		ID:       8,
		Platform: PlatformAntigravity,
		Type:     AccountTypeOAuth,
	}
	refresher := &tokenRefresherStub{
		credentials: map[string]any{
			"access_token": "ag-token",
		},
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.NoError(t, err)
	require.Equal(t, 1, repo.updateCalls)
	require.Equal(t, 1, invalidator.calls) // Antigravity 也应触发缓存失效
}

// TestTokenRefreshService_RefreshWithRetry_NonOAuthAccount 测试非 OAuth 账号不触发缓存失效
func TestTokenRefreshService_RefreshWithRetry_NonOAuthAccount(t *testing.T) {
	repo := &tokenRefreshAccountRepo{}
	invalidator := &tokenCacheInvalidatorStub{}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          1,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, nil)
	account := &Account{
		ID:       9,
		Platform: PlatformGemini,
		Type:     AccountTypeAPIKey, // 非 OAuth
	}
	refresher := &tokenRefresherStub{
		credentials: map[string]any{
			"access_token": "token",
		},
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.NoError(t, err)
	require.Equal(t, 1, repo.updateCalls)
	require.Equal(t, 0, invalidator.calls) // 非 OAuth 不触发缓存失效
}

// TestTokenRefreshService_RefreshWithRetry_OtherPlatformOAuth 测试所有 OAuth 平台都触发缓存失效
func TestTokenRefreshService_RefreshWithRetry_OtherPlatformOAuth(t *testing.T) {
	repo := &tokenRefreshAccountRepo{}
	invalidator := &tokenCacheInvalidatorStub{}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          1,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, nil)
	account := &Account{
		ID:       10,
		Platform: PlatformOpenAI, // OpenAI OAuth 账户
		Type:     AccountTypeOAuth,
	}
	refresher := &tokenRefresherStub{
		credentials: map[string]any{
			"access_token": "token",
		},
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.NoError(t, err)
	require.Equal(t, 1, repo.updateCalls)
	require.Equal(t, 1, invalidator.calls) // 所有 OAuth 账户刷新后触发缓存失效
}

// TestTokenRefreshService_RefreshWithRetry_UpdateFailed 测试更新失败的情况
func TestTokenRefreshService_RefreshWithRetry_UpdateFailed(t *testing.T) {
	repo := &tokenRefreshAccountRepo{updateErr: errors.New("update failed")}
	invalidator := &tokenCacheInvalidatorStub{}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          1,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, nil)
	account := &Account{
		ID:       11,
		Platform: PlatformGemini,
		Type:     AccountTypeOAuth,
	}
	refresher := &tokenRefresherStub{
		credentials: map[string]any{
			"access_token": "token",
		},
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to save credentials")
	require.Equal(t, 1, repo.updateCalls)
	require.Equal(t, 0, invalidator.calls) // 更新失败时不应触发缓存失效
}

// TestTokenRefreshService_RefreshWithRetry_RefreshFailed 测试可重试错误耗尽不标记 error
func TestTokenRefreshService_RefreshWithRetry_RefreshFailed(t *testing.T) {
	repo := &tokenRefreshAccountRepo{}
	invalidator := &tokenCacheInvalidatorStub{}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          2,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, nil)
	account := &Account{
		ID:       12,
		Platform: PlatformGemini,
		Type:     AccountTypeOAuth,
	}
	refresher := &tokenRefresherStub{
		err: errors.New("refresh failed"),
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.Error(t, err)
	require.Equal(t, 0, repo.updateCalls)   // 刷新失败不应更新
	require.Equal(t, 0, invalidator.calls)  // 刷新失败不应触发缓存失效
	require.Equal(t, 0, repo.setErrorCalls) // 可重试错误耗尽不标记 error，下个周期继续重试
}

// TestTokenRefreshService_RefreshWithRetry_AntigravityRefreshFailed 测试 Antigravity 刷新失败不设置错误状态
func TestTokenRefreshService_RefreshWithRetry_AntigravityRefreshFailed(t *testing.T) {
	repo := &tokenRefreshAccountRepo{}
	invalidator := &tokenCacheInvalidatorStub{}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          1,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, nil)
	account := &Account{
		ID:       13,
		Platform: PlatformAntigravity,
		Type:     AccountTypeOAuth,
	}
	refresher := &tokenRefresherStub{
		err: errors.New("network error"), // 可重试错误
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.Error(t, err)
	require.Equal(t, 0, repo.updateCalls)
	require.Equal(t, 0, invalidator.calls)
	require.Equal(t, 0, repo.setErrorCalls) // Antigravity 可重试错误不设置错误状态
}

// TestTokenRefreshService_RefreshWithRetry_AntigravityNonRetryableError 测试 Antigravity 不可重试错误
func TestTokenRefreshService_RefreshWithRetry_AntigravityNonRetryableError(t *testing.T) {
	repo := &tokenRefreshAccountRepo{}
	invalidator := &tokenCacheInvalidatorStub{}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          3,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, nil)
	account := &Account{
		ID:       14,
		Platform: PlatformAntigravity,
		Type:     AccountTypeOAuth,
	}
	refresher := &tokenRefresherStub{
		err: errors.New("invalid_grant: token revoked"), // 不可重试错误
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.Error(t, err)
	require.Equal(t, 0, repo.updateCalls)
	require.Equal(t, 0, invalidator.calls)
	require.Equal(t, 1, repo.setErrorCalls) // 不可重试错误应设置错误状态
}

// TestTokenRefreshService_RefreshWithRetry_ClearsTempUnschedulable 测试刷新成功后清除临时不可调度（DB + Redis）
func TestTokenRefreshService_RefreshWithRetry_ClearsTempUnschedulable(t *testing.T) {
	repo := &tokenRefreshAccountRepo{}
	invalidator := &tokenCacheInvalidatorStub{}
	tempCache := &tempUnschedCacheStub{}
	cfg := &config.Config{
		TokenRefresh: config.TokenRefreshConfig{
			MaxRetries:          1,
			RetryBackoffSeconds: 0,
		},
	}
	service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, tempCache)
	until := time.Now().Add(10 * time.Minute)
	account := &Account{
		ID:                     15,
		Platform:               PlatformGemini,
		Type:                   AccountTypeOAuth,
		TempUnschedulableUntil: &until,
	}
	refresher := &tokenRefresherStub{
		credentials: map[string]any{
			"access_token": "new-token",
		},
	}

	err := service.refreshWithRetry(context.Background(), account, refresher)
	require.NoError(t, err)
	require.Equal(t, 1, repo.updateCalls)
	require.Equal(t, 1, repo.clearTempCalls)   // DB 清除
	require.Equal(t, 1, tempCache.deleteCalls) // Redis 缓存也应清除
}

// TestTokenRefreshService_RefreshWithRetry_NonRetryableErrorAllPlatforms 测试所有平台不可重试错误都 SetError
func TestTokenRefreshService_RefreshWithRetry_NonRetryableErrorAllPlatforms(t *testing.T) {
	tests := []struct {
		name     string
		platform string
	}{
		{name: "gemini", platform: PlatformGemini},
		{name: "anthropic", platform: PlatformAnthropic},
		{name: "openai", platform: PlatformOpenAI},
		{name: "antigravity", platform: PlatformAntigravity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &tokenRefreshAccountRepo{}
			invalidator := &tokenCacheInvalidatorStub{}
			cfg := &config.Config{
				TokenRefresh: config.TokenRefreshConfig{
					MaxRetries:          3,
					RetryBackoffSeconds: 0,
				},
			}
			service := NewTokenRefreshService(repo, nil, nil, nil, nil, invalidator, nil, cfg, nil)
			account := &Account{
				ID:       16,
				Platform: tt.platform,
				Type:     AccountTypeOAuth,
			}
			refresher := &tokenRefresherStub{
				err: errors.New("invalid_grant: token revoked"),
			}

			err := service.refreshWithRetry(context.Background(), account, refresher)
			require.Error(t, err)
			require.Equal(t, 1, repo.setErrorCalls) // 所有平台不可重试错误都应 SetError
		})
	}
}

// --- 分布式锁协调路径测试 ---

// TestTokenRefreshService_Lock_Acquired_RefreshProceeds
// (a) 成功获取锁 → 从 DB 重读账号，继续执行刷新
func TestTokenRefreshService_Lock_Acquired_RefreshProceeds(t *testing.T) {
	const accountID = int64(100)
	freshAccount := &Account{
		ID:          accountID,
		Platform:    PlatformAnthropic,
		Type:        AccountTypeOAuth,
		Credentials: map[string]any{"refresh_token": "db-latest-rtoken"},
	}
	repo := &tokenRefreshAccountRepo{
		mockAccountRepoForGemini: mockAccountRepoForGemini{
			accountsByID: map[int64]*Account{accountID: freshAccount},
		},
	}
	locker := &refreshLockerStub{locked: true}
	cfg := &config.Config{TokenRefresh: config.TokenRefreshConfig{MaxRetries: 1}}
	svc := NewTokenRefreshService(repo, nil, nil, nil, nil, nil, nil, cfg, nil)
	svc.SetRefreshLocker(locker)

	refresher := &lockableRefresherStub{
		lockKey: "lock:account:100",
		creds:   map[string]any{"access_token": "new-at", "refresh_token": "new-rt"},
	}
	account := &Account{
		ID:          accountID,
		Platform:    PlatformAnthropic,
		Type:        AccountTypeOAuth,
		Credentials: map[string]any{"refresh_token": "stale-snapshot-rtoken"},
	}

	err := svc.refreshWithRetry(context.Background(), account, refresher)

	require.NoError(t, err)
	require.Equal(t, 1, locker.acquireCalls, "lock should be acquired once")
	require.Equal(t, 1, locker.releaseCalls, "lock should be released via defer")
	require.Equal(t, 1, repo.getByIDCalls, "account should be re-read from DB after acquiring lock")
	require.Equal(t, 1, refresher.refreshCalls, "refresh should proceed")
	require.Equal(t, 1, repo.updateCalls, "new credentials should be saved")
}

// TestTokenRefreshService_Lock_Held_SkipsRefresh
// (b) 锁被 TokenProvider 持有 → 不重读 DB，直接跳过刷新（即使 NeedsRefresh 仍为 true）
func TestTokenRefreshService_Lock_Held_SkipsRefresh(t *testing.T) {
	const accountID = int64(101)
	// 场景假设：DB 中账号其实已被 TokenProvider 刷新，expires_at 设为远期
	// （如果此时重读 DB，NeedsRefresh 将返回 false，但实现选择在锁被占用时不重读 DB）
	farFuture := time.Now().Add(2 * time.Hour).Unix()
	freshAccount := &Account{
		ID:       accountID,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"refresh_token": "provider-refreshed-rtoken",
			"expires_at":    fmt.Sprintf("%d", farFuture),
		},
	}
	repo := &tokenRefreshAccountRepo{
		mockAccountRepoForGemini: mockAccountRepoForGemini{
			accountsByID: map[int64]*Account{accountID: freshAccount},
		},
	}
	// locked=false, acquireErr=nil → lock held by another worker
	locker := &refreshLockerStub{locked: false, acquireErr: nil}
	cfg := &config.Config{TokenRefresh: config.TokenRefreshConfig{MaxRetries: 1}}
	svc := NewTokenRefreshService(repo, nil, nil, nil, nil, nil, nil, cfg, nil)
	svc.SetRefreshLocker(locker)

	refresher := &lockableRefresherStub{
		lockKey: "lock:account:101",
		creds:   map[string]any{"access_token": "should-not-be-used"},
	}
	account := &Account{
		ID:       accountID,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"refresh_token": "stale-rtoken",
			"expires_at":    "0",
		},
	}

	err := svc.refreshWithRetry(context.Background(), account, refresher)

	require.NoError(t, err)
	require.Equal(t, 1, locker.acquireCalls)
	require.Equal(t, 0, locker.releaseCalls, "lock was never held, no release needed")
	require.Equal(t, 0, repo.getByIDCalls, "DB re-read skipped when lock is held")
	require.Equal(t, 0, refresher.refreshCalls, "refresh must be skipped when lock is held")
	require.Equal(t, 0, repo.updateCalls)
}

// TestTokenRefreshService_Lock_Error_DegradedRefreshProceeds
// (c) 获取锁时 Redis 报错 → 降级为无锁刷新，先从 DB 重读再继续
func TestTokenRefreshService_Lock_Error_DegradedRefreshProceeds(t *testing.T) {
	const accountID = int64(102)
	freshAccount := &Account{
		ID:          accountID,
		Platform:    PlatformAnthropic,
		Type:        AccountTypeOAuth,
		Credentials: map[string]any{"refresh_token": "db-rtoken"},
	}
	repo := &tokenRefreshAccountRepo{
		mockAccountRepoForGemini: mockAccountRepoForGemini{
			accountsByID: map[int64]*Account{accountID: freshAccount},
		},
	}
	locker := &refreshLockerStub{acquireErr: errors.New("redis: connection refused")}
	cfg := &config.Config{TokenRefresh: config.TokenRefreshConfig{MaxRetries: 1}}
	svc := NewTokenRefreshService(repo, nil, nil, nil, nil, nil, nil, cfg, nil)
	svc.SetRefreshLocker(locker)

	refresher := &lockableRefresherStub{
		lockKey: "lock:account:102",
		creds:   map[string]any{"access_token": "new-at"},
	}
	account := &Account{
		ID:          accountID,
		Platform:    PlatformAnthropic,
		Type:        AccountTypeOAuth,
		Credentials: map[string]any{"refresh_token": "stale-rtoken"},
	}

	err := svc.refreshWithRetry(context.Background(), account, refresher)

	require.NoError(t, err, "lock error should degrade gracefully, not fail the refresh")
	require.Equal(t, 1, locker.acquireCalls)
	require.Equal(t, 0, locker.releaseCalls, "lock was not acquired, no release")
	require.Equal(t, 1, repo.getByIDCalls, "DB should be re-read even on lock error to reduce stale-snapshot window")
	require.Equal(t, 1, refresher.refreshCalls, "refresh should proceed in degraded mode")
	require.Equal(t, 1, repo.updateCalls)
}

// TestIsNonRetryableRefreshError 测试不可重试错误判断
func TestIsNonRetryableRefreshError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{name: "nil_error", err: nil, expected: false},
		{name: "network_error", err: errors.New("network timeout"), expected: false},
		{name: "invalid_grant", err: errors.New("invalid_grant"), expected: true},
		{name: "invalid_client", err: errors.New("invalid_client"), expected: true},
		{name: "unauthorized_client", err: errors.New("unauthorized_client"), expected: true},
		{name: "access_denied", err: errors.New("access_denied"), expected: true},
		{name: "invalid_grant_with_desc", err: errors.New("Error: invalid_grant - token revoked"), expected: true},
		{name: "case_insensitive", err: errors.New("INVALID_GRANT"), expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNonRetryableRefreshError(tt.err)
			require.Equal(t, tt.expected, result)
		})
	}
}
