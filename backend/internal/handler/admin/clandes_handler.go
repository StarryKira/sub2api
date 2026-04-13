package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// ClandesHandler exposes clandes integration status and control to the admin UI.
type ClandesHandler struct {
	client      *service.ClandesClient   // may be nil when clandes.enabled=false
	accountRepo service.AccountRepository
}

// NewClandesHandler creates a ClandesHandler.
// client may be nil if clandes integration is disabled.
func NewClandesHandler(client *service.ClandesClient, accountRepo service.AccountRepository) *ClandesHandler {
	return &ClandesHandler{
		client:      client,
		accountRepo: accountRepo,
	}
}

// GetStatus returns the current clandes integration status.
// GET /api/v1/admin/clandes/status
func (h *ClandesHandler) GetStatus(c *gin.Context) {
	if h.client == nil {
		response.Success(c, service.ClandesStatus{
			Enabled:   false,
			Connected: false,
			Addr:      "",
		})
		return
	}
	response.Success(c, h.client.Status())
}

// SyncAccounts triggers a manual re-sync of all Anthropic accounts to clandes.
// POST /api/v1/admin/clandes/sync
func (h *ClandesHandler) SyncAccounts(c *gin.Context) {
	if h.client == nil {
		response.Error(c, http.StatusServiceUnavailable, "clandes integration is not enabled")
		return
	}
	if err := service.SyncAccountsByRepo(c.Request.Context(), h.client, h.accountRepo); err != nil {
		response.Error(c, http.StatusInternalServerError, err.Error())
		return
	}
	response.Success(c, gin.H{"message": "accounts synced successfully"})
}
