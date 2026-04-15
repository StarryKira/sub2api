package service

import (
	"context"
	"strconv"
	"time"

	"go.uber.org/zap"

	proto "github.com/Wei-Shaw/sub2api/internal/pkg/clandes/proto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

// clandesRouterImpl implements proto.Router_Server — the Cap'n Proto callback
// interface that clandes calls into for routing decisions and usage reporting.
type clandesRouterImpl struct {
	reqCache            *clandesRequestCache
	gatewayService      *GatewayService
	billingCacheService *BillingCacheService
	apiKeyService       *APIKeyService
	subscriptionService *SubscriptionService
}

func newClandesRouterImpl(
	reqCache *clandesRequestCache,
	gatewaySvc *GatewayService,
	billingSvc *BillingCacheService,
	apiKeySvc *APIKeyService,
	subSvc *SubscriptionService,
) *clandesRouterImpl {
	return &clandesRouterImpl{
		reqCache:            reqCache,
		gatewayService:      gatewaySvc,
		billingCacheService: billingSvc,
		apiKeyService:       apiKeySvc,
		subscriptionService: subSvc,
	}
}

// RouteRequest is called by clandes before forwarding a request upstream.
// It validates the API key, checks billing eligibility, selects an account,
// and caches context for the subsequent reportUsage call.
//
// Returns RouteResult.routed with accountId on success, or RouteResult.rejected on failure.
func (r *clandesRouterImpl) RouteRequest(ctx context.Context, call proto.Router_routeRequest) error {
	args := call.Args()

	requestID, _ := args.RequestId()
	apiKeyStr, _ := args.ApiKey()
	model, _ := args.Model()
	userAgent, _ := args.UserAgent()
	sessionID, _ := args.SessionId()

	log := logger.L().With(
		zap.String("component", "clandes.router"),
		zap.String("request_id", requestID),
		zap.String("model", model),
	)

	reject := func(statusCode uint16, message string) error {
		res, err := call.AllocResults()
		if err != nil {
			return err
		}
		result, err := res.NewResult()
		if err != nil {
			return err
		}
		result.SetRejected()
		result.Rejected().SetStatusCode(statusCode)
		return result.Rejected().SetMessage_(message)
	}

	// 1. Look up API key (uses auth cache)
	apiKey, err := r.apiKeyService.GetByKey(ctx, apiKeyStr)
	if err != nil {
		log.Warn("routeRequest: api key not found", zap.Error(err))
		return reject(401, "invalid api key")
	}
	if apiKey.User == nil {
		log.Warn("routeRequest: api key has no user")
		return reject(401, "api key has no user")
	}

	// 2. Check billing eligibility
	var group *Group
	if apiKey.Group != nil {
		group = apiKey.Group
	}
	if err := r.billingCacheService.CheckBillingEligibility(ctx, apiKey.User, apiKey, group, nil); err != nil {
		log.Info("routeRequest: billing eligibility failed", zap.Error(err))
		return reject(403, err.Error())
	}

	// 3. Select account (set Claude Code client flag from User-Agent)
	if claudeCodeUAPattern.MatchString(userAgent) {
		ctx = SetClaudeCodeClient(ctx, true)
	}
	selection, err := r.gatewayService.SelectAccountWithLoadAwareness(
		ctx,
		apiKey.GroupID,
		sessionID,
		model,
		nil,
		"",
		0,
	)
	if err != nil {
		log.Warn("routeRequest: no available account", zap.Error(err))
		return reject(503, "no available account")
	}
	account := selection.Account
	// Release the slot immediately — clandes manages its own concurrency.
	if selection.Acquired && selection.ReleaseFunc != nil {
		selection.ReleaseFunc()
	}

	// Bind sticky session so subsequent requests in the same Claude Code session
	// route to the same account (preserves prompt cache).
	if sessionID != "" {
		_ = r.gatewayService.BindStickySession(ctx, apiKey.GroupID, sessionID, account.ID)
	}

	// 4. Resolve subscription for subscription-type groups
	var subscription *UserSubscription
	if apiKey.Group != nil && apiKey.Group.IsSubscriptionType() && r.subscriptionService != nil {
		if sub, err := r.subscriptionService.GetActiveSubscription(ctx, apiKey.User.ID, *apiKey.GroupID); err == nil {
			subscription = sub
		}
	}

	// 5. Cache context for reportUsage
	r.reqCache.set(requestID, &clandesRequestContext{
		APIKey:       apiKey,
		User:         apiKey.User,
		Account:      account,
		Subscription: subscription,
		GroupID:      apiKey.GroupID,
		StartTime:    time.Now(),
		UserAgent:    userAgent,
	})

	log.Info("routeRequest: routed", zap.Int64("account_id", account.ID))

	// 5. Return RouteResult.routed
	res, err := call.AllocResults()
	if err != nil {
		return err
	}
	result, err := res.NewResult()
	if err != nil {
		return err
	}
	result.SetRouted()
	routed := result.Routed()
	if err := routed.SetAccountId(strconv.FormatInt(account.ID, 10)); err != nil {
		return err
	}
	routed.SetThinkingLevelOverride(proto.ThinkingLevelOverride_noOverride)
	// Non-Claude-Code clients can't produce the correct billing header hash;
	// tell the proxy to skip that check.
	routed.SetSkipBillingCheck(!claudeCodeUAPattern.MatchString(userAgent))
	return nil
}

// ReportUsage is called by clandes after a request completes (fire-and-forget).
// It maps usage data to sub2api's billing system.
func (r *clandesRouterImpl) ReportUsage(ctx context.Context, call proto.Router_reportUsage) error {
	args := call.Args()

	requestID, _ := args.RequestId()
	report, err := args.Report()
	if err != nil {
		return nil // best-effort
	}

	log := logger.L().With(
		zap.String("component", "clandes.router"),
		zap.String("request_id", requestID),
	)

	// Retrieve cached context from routeRequest
	rctx, ok := r.reqCache.getAndDelete(requestID)
	if !ok {
		log.Warn("reportUsage: no cached context (expired or unknown request_id)")
		return nil
	}

	model, _ := report.Model()
	durationMs := report.DurationMs()
	inputTokens := report.InputTokens()
	outputTokens := report.OutputTokens()
	statusCode := report.StatusCode()
	cacheReadTokens := report.CacheReadTokens()
	cacheWriteTokens := report.CacheWriteTokens()

	result := &ForwardResult{
		Model:    model,
		Duration: time.Duration(durationMs) * time.Millisecond,
		Usage: ClaudeUsage{
			InputTokens:              int(inputTokens),
			OutputTokens:             int(outputTokens),
			CacheReadInputTokens:     int(cacheReadTokens),
			CacheCreationInputTokens: int(cacheWriteTokens),
		},
	}

	log.Info("reportUsage: recording",
		zap.String("model", model),
		zap.Int("input_tokens", int(inputTokens)),
		zap.Int("output_tokens", int(outputTokens)),
		zap.Int("cache_read_tokens", int(cacheReadTokens)),
		zap.Int("cache_write_tokens", int(cacheWriteTokens)),
		zap.Int("status_code", int(statusCode)),
	)

	// Record billing asynchronously to avoid blocking the capnp callback goroutine
	go func() {
		bctx := context.Background()
		if err := r.gatewayService.RecordUsage(bctx, &RecordUsageInput{
			Result:           result,
			APIKey:           rctx.APIKey,
			User:             rctx.User,
			Account:          rctx.Account,
			Subscription:     rctx.Subscription,
			InboundEndpoint:  "/v1/messages",
			UpstreamEndpoint: "/v1/messages",
			UserAgent:        rctx.UserAgent,
			APIKeyService:    r.apiKeyService,
		}); err != nil {
			log.Error("reportUsage: RecordUsage failed", zap.Error(err))
		}
	}()

	return nil
}

// ReportChunk is called for each SSE chunk during streaming (fire-and-forget).
// Currently a no-op; reserved for future streaming analytics.
func (r *clandesRouterImpl) ReportChunk(_ context.Context, _ proto.Router_reportChunk) error {
	return nil
}

// OnAccountEvent is called by clandes when an account lifecycle event occurs.
// Currently logs only; reserved for future account state synchronization.
func (r *clandesRouterImpl) OnAccountEvent(_ context.Context, call proto.Router_onAccountEvent) error {
	args := call.Args()
	accountID, _ := args.AccountId()
	kind := args.Kind()
	logger.L().Info("clandes: onAccountEvent",
		zap.String("component", "clandes.router"),
		zap.String("account_id", accountID),
		zap.String("kind", kind.String()),
	)
	return nil
}
