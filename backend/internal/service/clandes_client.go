package service

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"capnproto.org/go/capnp/v3/rpc"
	"capnproto.org/go/capnp/v3/rpc/transport"
	"go.uber.org/zap"

	proto "github.com/Wei-Shaw/sub2api/internal/pkg/clandes/proto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

// ClandesClient manages the Cap'n Proto RPC connection to the clandes server.
// It handles:
//   - Connecting and authenticating via Bootstrap.auth()
//   - Syncing accounts from sub2api to clandes via AccountService
//   - Registering the billing Router callback via PolicyService
//   - Automatic reconnection on disconnect
type ClandesClient struct {
	addr              string
	authToken         string
	reconnectInterval time.Duration

	mu          sync.Mutex
	conn        *rpc.Conn
	service     proto.ClandesService
	accountSvc  proto.AccountService
	authSvc     proto.ClaudeAuthService
	querySvc    proto.ClaudeQueryService
	policySvc proto.PolicyService

	routerImpl *clandesRouterImpl // owns the Router server capability
	reqCache   *clandesRequestCache

	// injected dependencies
	gatewayService      *GatewayService
	billingCacheService *BillingCacheService
	apiKeyService       *APIKeyService

	closed    chan struct{}
	closeOnce sync.Once
}

// NewClandesClient creates a ClandesClient. Call Start() to connect.
func NewClandesClient(
	addr string,
	authToken string,
	reconnectInterval int,
	gatewayService *GatewayService,
	billingCacheService *BillingCacheService,
	apiKeyService *APIKeyService,
) *ClandesClient {
	interval := time.Duration(reconnectInterval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &ClandesClient{
		addr:                addr,
		authToken:           authToken,
		reconnectInterval:   interval,
		gatewayService:      gatewayService,
		billingCacheService: billingCacheService,
		apiKeyService:       apiKeyService,
		reqCache:            newClandesRequestCache(),
		closed:              make(chan struct{}),
	}
}

// Start connects to clandes, syncs accounts, registers the Router callback,
// and launches a background goroutine to reconnect on disconnect.
func (c *ClandesClient) Start(ctx context.Context, syncAccounts func(ctx context.Context, client *ClandesClient) error) error {
	if err := c.connect(ctx); err != nil {
		return fmt.Errorf("clandes: initial connect: %w", err)
	}
	if syncAccounts != nil {
		if err := syncAccounts(ctx, c); err != nil {
			logger.L().Warn("clandes: account sync failed (non-fatal)", zap.Error(err))
		}
	}
	if err := c.registerCallback(ctx); err != nil {
		return fmt.Errorf("clandes: register callback: %w", err)
	}
	go c.reconnectLoop(syncAccounts)
	return nil
}

// Close shuts down the connection and the reconnect loop.
func (c *ClandesClient) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.releaseCapabilities()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
	})
}

// ClandesStatus holds the current state of the clandes integration for API responses.
type ClandesStatus struct {
	Enabled   bool   `json:"enabled"`
	Connected bool   `json:"connected"`
	Addr      string `json:"addr"`
}

// Status returns the current connection status of the client.
func (c *ClandesClient) Status() ClandesStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	connected := c.conn != nil && c.service.IsValid()
	return ClandesStatus{
		Enabled:   true,
		Connected: connected,
		Addr:      c.addr,
	}
}

// StartOAuthLogin initiates a Claude OAuth login via clandes's ClaudeAuthService.
// Returns (authUrl, sessionId) for the frontend to redirect the user.
func (c *ClandesClient) StartOAuthLogin(ctx context.Context, redirectURI, proxyURL string) (authURL, sessionID string, err error) {
	c.mu.Lock()
	if !c.authSvc.IsValid() {
		c.mu.Unlock()
		return "", "", fmt.Errorf("clandes: not connected")
	}
	authSvc := c.authSvc.AddRef()
	c.mu.Unlock()
	defer authSvc.Release()

	fut, rel := authSvc.StartLogin(ctx, func(p proto.ClaudeAuthService_startLogin_Params) error {
		if err := p.SetRedirectUri(redirectURI); err != nil {
			return err
		}
		if proxyURL != "" {
			if err := p.SetProxyUrl(proxyURL); err != nil {
				return err
			}
		}
		return nil
	})
	defer rel()

	res, err := fut.Struct()
	if err != nil {
		return "", "", fmt.Errorf("clandes: startLogin: %w", err)
	}
	authURL, _ = res.AuthUrl()
	sessionID, _ = res.SessionId()
	return authURL, sessionID, nil
}

// CompleteOAuthLogin exchanges the OAuth code for tokens via clandes.
func (c *ClandesClient) CompleteOAuthLogin(ctx context.Context, sessionID, code, callbackURL string) (*OAuthLoginResult, error) {
	c.mu.Lock()
	if !c.authSvc.IsValid() {
		c.mu.Unlock()
		return nil, fmt.Errorf("clandes: not connected")
	}
	authSvc := c.authSvc.AddRef()
	c.mu.Unlock()
	defer authSvc.Release()

	fut, rel := authSvc.CompleteLogin(ctx, func(p proto.ClaudeAuthService_completeLogin_Params) error {
		if err := p.SetSessionId(sessionID); err != nil {
			return err
		}
		if err := p.SetCode(code); err != nil {
			return err
		}
		return p.SetCallbackUrl(callbackURL)
	})
	defer rel()

	res, err := fut.Struct()
	if err != nil {
		return nil, fmt.Errorf("clandes: completeLogin: %w", err)
	}
	if !res.Success() {
		msg, _ := res.Message_()
		return nil, fmt.Errorf("clandes: completeLogin failed: %s", msg)
	}
	accessToken, _ := res.AccessToken()
	refreshToken, _ := res.RefreshToken()
	email, _ := res.Email()
	orgID, _ := res.OrganizationId()
	return &OAuthLoginResult{
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		ExpiresIn:      res.ExpiresIn(),
		Email:          email,
		OrganizationID: orgID,
	}, nil
}

// OAuthLoginResult holds the tokens from a successful OAuth login.
type OAuthLoginResult struct {
	AccessToken    string
	RefreshToken   string
	ExpiresIn      uint64
	Email          string
	OrganizationID string
}

// GetUsage fetches account usage (5h/7d quota) via ClaudeQueryService RPC.
func (c *ClandesClient) GetUsage(ctx context.Context, accountID string) (*UsageInfo, error) {
	c.mu.Lock()
	if !c.querySvc.IsValid() {
		c.mu.Unlock()
		return nil, fmt.Errorf("clandes: not connected")
	}
	querySvc := c.querySvc.AddRef()
	c.mu.Unlock()
	defer querySvc.Release()

	fut, rel := querySvc.GetUsage(ctx, func(p proto.ClaudeQueryService_getUsage_Params) error {
		return p.SetAccountId(accountID)
	})
	defer rel()

	res, err := fut.Struct()
	if err != nil {
		return nil, fmt.Errorf("clandes: GetUsage RPC: %w", err)
	}
	if !res.Success() {
		msg, _ := res.Message_()
		return nil, fmt.Errorf("clandes: GetUsage failed: %s", msg)
	}

	return buildClandesUsageInfo(res)
}

// buildClandesUsageInfo maps ClaudeQueryService.getUsage results to UsageInfo.
func buildClandesUsageInfo(res proto.ClaudeQueryService_getUsage_Results) (*UsageInfo, error) {
	now := time.Now()
	info := &UsageInfo{
		Source:    "active",
		UpdatedAt: &now,
	}

	// 5-hour window
	if res.HasFiveHour() {
		fh, err := res.FiveHour()
		if err == nil {
			info.FiveHour = usagePeriodToProgress(fh)
		}
	}

	// 7-day window
	if res.HasSevenDay() {
		sd, err := res.SevenDay()
		if err == nil {
			p := usagePeriodToProgress(sd)
			if p.ResetsAt != nil {
				info.SevenDay = p
			}
		}
	}

	// 7-day sonnet window
	if res.HasSevenDaySonnet() {
		ss, err := res.SevenDaySonnet()
		if err == nil {
			p := usagePeriodToProgress(ss)
			if p.ResetsAt != nil {
				info.SevenDaySonnet = p
			}
		}
	}

	return info, nil
}

func usagePeriodToProgress(p proto.UsagePeriod) *UsageProgress {
	prog := &UsageProgress{
		Utilization: p.Utilization(),
	}
	resetsAt, err := p.ResetsAt()
	if err == nil && resetsAt != "" {
		if t, err := time.Parse(time.RFC3339, resetsAt); err == nil {
			prog.ResetsAt = &t
			prog.RemainingSeconds = int(time.Until(t).Seconds())
		}
	}
	return prog
}

// AccountService returns the clandes AccountService client. Caller must call Release() when done.
func (c *ClandesClient) AccountService() (proto.AccountService, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.accountSvc.IsValid() {
		return proto.AccountService{}, fmt.Errorf("clandes: not connected")
	}
	return c.accountSvc.AddRef(), nil
}

// --- internal ---

func (c *ClandesClient) connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close stale connection if any
	if c.conn != nil {
		c.releaseCapabilities()
		c.conn.Close()
		c.conn = nil
	}

	conn, err := net.DialTimeout("tcp", c.addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.addr, err)
	}

	rpcConn := rpc.NewConn(transport.NewStream(conn), &rpc.Options{
		// We are the client; no BootstrapClient needed on our side.
	})
	c.conn = rpcConn

	// Bootstrap: get the Bootstrap capability
	bootstrapClient := rpcConn.Bootstrap(ctx)
	bootstrap := proto.Bootstrap(bootstrapClient)

	// Authenticate
	authFut, rel := bootstrap.Auth(ctx, func(p proto.Bootstrap_auth_Params) error {
		return p.SetToken(c.authToken)
	})
	defer rel()

	res, err := authFut.Struct()
	if err != nil {
		bootstrap.Release()
		return fmt.Errorf("clandes: auth: %w", err)
	}
	bootstrap.Release()

	svc := res.Service()
	c.service = svc.AddRef()

	// Get AccountService sub-capability
	acctFut, acctRel := c.service.AccountService(ctx, nil)
	defer acctRel()
	acctRes, err := acctFut.Struct()
	if err != nil {
		return fmt.Errorf("clandes: get AccountService: %w", err)
	}
	c.accountSvc = acctRes.Svc().AddRef()

	// Get ClaudeAuthService sub-capability
	caFut, caRel := c.service.ClaudeAuthService(ctx, nil)
	defer caRel()
	caRes, err := caFut.Struct()
	if err != nil {
		return fmt.Errorf("clandes: get ClaudeAuthService: %w", err)
	}
	c.authSvc = caRes.Svc().AddRef()

	// Get ClaudeQueryService sub-capability
	cqFut, cqRel := c.service.ClaudeQueryService(ctx, nil)
	defer cqRel()
	cqRes, err := cqFut.Struct()
	if err != nil {
		return fmt.Errorf("clandes: get ClaudeQueryService: %w", err)
	}
	c.querySvc = cqRes.Svc().AddRef()

	// Get PolicyService sub-capability
	cbFut, cbRel := c.service.PolicyService(ctx, nil)
	defer cbRel()
	cbRes, err := cbFut.Struct()
	if err != nil {
		return fmt.Errorf("clandes: get PolicyService: %w", err)
	}
	c.policySvc = cbRes.Svc().AddRef()

	logger.L().Info("clandes: connected", zap.String("addr", c.addr))
	return nil
}

func (c *ClandesClient) registerCallback(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build the Router server
	c.routerImpl = newClandesRouterImpl(c.reqCache, c.gatewayService, c.billingCacheService, c.apiKeyService)
	routerClient := proto.Router_ServerToClient(c.routerImpl)

	// Register with clandes
	connFut, rel := c.policySvc.Connect(ctx, func(p proto.PolicyService_connect_Params) error {
		p.SetRouter(routerClient)
		return nil
	})
	defer rel()

	if _, err := connFut.Struct(); err != nil {
		return fmt.Errorf("clandes: PolicyService.connect: %w", err)
	}
	logger.L().Info("clandes: Router callback registered")
	return nil
}

func (c *ClandesClient) reconnectLoop(syncAccounts func(ctx context.Context, client *ClandesClient) error) {
	for {
		select {
		case <-c.closed:
			return
		case <-c.conn.Done():
			logger.L().Warn("clandes: connection lost, reconnecting", zap.Duration("in", c.reconnectInterval))
		}

		select {
		case <-c.closed:
			return
		case <-time.After(c.reconnectInterval):
		}

		ctx := context.Background()
		if err := c.connect(ctx); err != nil {
			logger.L().Error("clandes: reconnect failed", zap.Error(err))
			continue
		}
		if syncAccounts != nil {
			if err := syncAccounts(ctx, c); err != nil {
				logger.L().Warn("clandes: account re-sync failed", zap.Error(err))
			}
		}
		if err := c.registerCallback(ctx); err != nil {
			logger.L().Error("clandes: re-register callback failed", zap.Error(err))
		}
	}
}

func (c *ClandesClient) releaseCapabilities() {
	if c.accountSvc.IsValid() {
		c.accountSvc.Release()
		c.accountSvc = proto.AccountService{}
	}
	if c.authSvc.IsValid() {
		c.authSvc.Release()
		c.authSvc = proto.ClaudeAuthService{}
	}
	if c.querySvc.IsValid() {
		c.querySvc.Release()
		c.querySvc = proto.ClaudeQueryService{}
	}
	if c.policySvc.IsValid() {
		c.policySvc.Release()
		c.policySvc = proto.PolicyService{}
	}
	if c.service.IsValid() {
		c.service.Release()
		c.service = proto.ClandesService{}
	}
}

