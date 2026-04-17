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
	ReleaseFunc  func() // concurrency slot release; called in ReportUsage or on disconnect cleanup
}

// clandesRequestCache is a short-lived cache bridging routeRequest and reportUsage calls.
// TTL is 5 minutes; entries are cleaned up on reportUsage or on expiry.
type clandesRequestCache struct {
	cache *gocache.Cache
}

const clandesRequestCacheTTL = 5 * time.Minute

func newClandesRequestCache() *clandesRequestCache {
	c := gocache.New(clandesRequestCacheTTL, clandesRequestCacheTTL*2)
	// Release concurrency slots when entries expire without a ReportUsage call
	// (e.g. clandes crashed mid-request and never reported back).
	c.OnEvicted(func(_ string, v any) {
		if ctx, ok := v.(*clandesRequestContext); ok && ctx.ReleaseFunc != nil {
			ctx.ReleaseFunc()
		}
	})
	return &clandesRequestCache{cache: c}
}

func (c *clandesRequestCache) set(requestID string, ctx *clandesRequestContext) {
	c.cache.Set(requestID, ctx, clandesRequestCacheTTL)
}

// getAndDelete retrieves and removes the context atomically. Returns (nil, false) if not found.
// The caller is responsible for calling ReleaseFunc; it is nil'd out here to prevent
// the OnEvicted callback from double-releasing.
func (c *clandesRequestCache) getAndDelete(requestID string) (*clandesRequestContext, bool) {
	v, ok := c.cache.Get(requestID)
	if !ok {
		return nil, false
	}
	ctx, ok := v.(*clandesRequestContext)
	if ok && ctx != nil {
		ctx.ReleaseFunc = nil // prevent OnEvicted from double-releasing
	}
	c.cache.Delete(requestID)
	return ctx, ok
}

// flushAll releases all in-flight concurrency slots and clears the cache.
// Called when the clandes connection drops to clean up orphaned slots.
func (c *clandesRequestCache) flushAll() int {
	items := c.cache.Items()
	count := 0
	for key, item := range items {
		if ctx, ok := item.Object.(*clandesRequestContext); ok && ctx.ReleaseFunc != nil {
			ctx.ReleaseFunc()
			ctx.ReleaseFunc = nil // prevent OnEvicted from double-releasing
			count++
		}
		c.cache.Delete(key)
	}
	return count
}
