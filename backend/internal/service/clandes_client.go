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
//   - Registering the billing Router callback via CallbackService
//   - Automatic reconnection on disconnect
type ClandesClient struct {
	addr              string
	authToken         string
	reconnectInterval time.Duration

	mu          sync.Mutex
	conn        *rpc.Conn
	service     proto.ClandesService
	accountSvc  proto.AccountService
	callbackSvc proto.CallbackService

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

	// Get CallbackService sub-capability
	cbFut, cbRel := c.service.CallbackService(ctx, nil)
	defer cbRel()
	cbRes, err := cbFut.Struct()
	if err != nil {
		return fmt.Errorf("clandes: get CallbackService: %w", err)
	}
	c.callbackSvc = cbRes.Svc().AddRef()

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
	connFut, rel := c.callbackSvc.Connect(ctx, func(p proto.CallbackService_connect_Params) error {
		p.SetRouter(routerClient)
		return nil
	})
	defer rel()

	if _, err := connFut.Struct(); err != nil {
		return fmt.Errorf("clandes: CallbackService.connect: %w", err)
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
	if c.callbackSvc.IsValid() {
		c.callbackSvc.Release()
		c.callbackSvc = proto.CallbackService{}
	}
	if c.service.IsValid() {
		c.service.Release()
		c.service = proto.ClandesService{}
	}
}

