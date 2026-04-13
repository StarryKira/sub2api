package service

import (
	"time"

	gocache "github.com/patrickmn/go-cache"
)

// clandesRequestContext stores the billing context for an in-flight request routed through clandes.
// It is keyed by the requestId from routeRequest and consumed in reportUsage.
type clandesRequestContext struct {
	APIKey       *APIKey
	User         *User
	Account      *Account
	Subscription *UserSubscription
	GroupID      *int64
	StartTime    time.Time
	UserAgent    string
}

// clandesRequestCache is a short-lived cache bridging routeRequest and reportUsage calls.
// TTL is 5 minutes; entries are cleaned up on reportUsage or on expiry.
type clandesRequestCache struct {
	cache *gocache.Cache
}

const clandesRequestCacheTTL = 5 * time.Minute

func newClandesRequestCache() *clandesRequestCache {
	return &clandesRequestCache{
		cache: gocache.New(clandesRequestCacheTTL, clandesRequestCacheTTL*2),
	}
}

func (c *clandesRequestCache) set(requestID string, ctx *clandesRequestContext) {
	c.cache.Set(requestID, ctx, clandesRequestCacheTTL)
}

// getAndDelete retrieves and removes the context atomically. Returns (nil, false) if not found.
func (c *clandesRequestCache) getAndDelete(requestID string) (*clandesRequestContext, bool) {
	v, ok := c.cache.Get(requestID)
	if !ok {
		return nil, false
	}
	c.cache.Delete(requestID)
	ctx, ok := v.(*clandesRequestContext)
	return ctx, ok
}
