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
	proxyRepo   service.ProxyRepository
}

// NewClandesHandler creates a ClandesHandler.
func NewClandesHandler(client *service.ClandesClient, accountRepo service.AccountRepository, proxyRepo service.ProxyRepository) *ClandesHandler {
	return &ClandesHandler{
		client:      client,
		accountRepo: accountRepo,
		proxyRepo:   proxyRepo,
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

// SyncAccounts triggers a manual re-sync of clandes-flagged accounts.
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

// StartOAuthLogin initiates OAuth login via clandes's ClaudeAuthService.
// POST /api/v1/admin/clandes/oauth/start
func (h *ClandesHandler) StartOAuthLogin(c *gin.Context) {
	if h.client == nil {
		response.Error(c, http.StatusServiceUnavailable, "clandes integration is not enabled")
		return
	}
	var req struct {
		RedirectURI string `json:"redirect_uri" binding:"required"`
		ProxyID     *int64 `json:"proxy_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	var proxyURL string
	if req.ProxyID != nil {
		if p, err := h.proxyRepo.GetByID(c.Request.Context(), *req.ProxyID); err == nil && p != nil {
			proxyURL = service.BuildProxyURL(p)
		}
	}
	authURL, sessionID, err := h.client.StartOAuthLogin(c.Request.Context(), req.RedirectURI, proxyURL)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, err.Error())
		return
	}
	response.Success(c, gin.H{"auth_url": authURL, "session_id": sessionID})
}

// CompleteOAuthLogin exchanges the code for tokens via clandes (token exchange only, no account creation).
// POST /api/v1/admin/clandes/oauth/exchange
func (h *ClandesHandler) CompleteOAuthLogin(c *gin.Context) {
	if h.client == nil {
		response.Error(c, http.StatusServiceUnavailable, "clandes integration is not enabled")
		return
	}
	var req struct {
		SessionID   string `json:"session_id" binding:"required"`
		Code        string `json:"code" binding:"required"`
		CallbackURL string `json:"callback_url" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.client.CompleteOAuthLogin(c.Request.Context(), req.SessionID, req.Code, req.CallbackURL)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, err.Error())
		return
	}
	response.Success(c, gin.H{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_in":    result.ExpiresIn,
		"email":         result.Email,
		"org_uuid":      result.OrganizationID,
	})
}
