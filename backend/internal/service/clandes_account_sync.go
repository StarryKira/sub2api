package service

import (
	"context"
	"fmt"
	"strconv"

	capnp "capnproto.org/go/capnp/v3"
	"go.uber.org/zap"

	proto "github.com/Wei-Shaw/sub2api/internal/pkg/clandes/proto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

// SyncAccountsToClandes registers all active Anthropic accounts from sub2api
// into clandes via the AccountService capnp RPC.
//
// Only Anthropic platform accounts (OAuth, SetupToken, APIKey) are synced —
// clandes currently supports Claude only.
func SyncAccountsToClandes(ctx context.Context, client *ClandesClient, accountService *AccountService) error {
	return SyncAccountsByRepo(ctx, client, accountService.accountRepo)
}

// IsClandesAccount returns true if the account is marked for clandes-only routing.
// Clandes accounts have {"clandes": true} in their Extra JSONB field.
// They are managed by clandes for TLS fingerprinting and OAuth refresh;
// sub2api only handles routing decisions and billing.
func IsClandesAccount(acc *Account) bool {
	if acc.Extra == nil {
		return false
	}
	v, ok := acc.Extra["clandes"].(bool)
	return ok && v
}

// SyncAccountsByRepo is like SyncAccountsToClandes but accepts AccountRepository directly.
// Only syncs accounts marked with {"clandes": true} in Extra.
func SyncAccountsByRepo(ctx context.Context, client *ClandesClient, repo AccountRepository) error {
	accounts, err := repo.ListByPlatform(ctx, PlatformAnthropic)
	if err != nil {
		return fmt.Errorf("clandes account sync: list accounts: %w", err)
	}

	svc, err := client.AccountService()
	if err != nil {
		return fmt.Errorf("clandes account sync: get AccountService: %w", err)
	}
	defer svc.Release()

	log := logger.L().With(zap.String("component", "clandes.account_sync"))
	synced := 0

	for i := range accounts {
		acc := &accounts[i]
		if acc.Status != "active" || !IsClandesAccount(acc) {
			continue
		}
		if err := registerAccountToClandes(ctx, svc, acc); err != nil {
			log.Warn("clandes account sync: failed to register account",
				zap.Int64("account_id", acc.ID),
				zap.String("account_type", acc.Type),
				zap.Error(err),
			)
			continue
		}
		synced++
	}

	log.Info("clandes account sync: done", zap.Int("synced", synced), zap.Int("total", len(accounts)))
	return nil
}

// registerAccountToClandes registers a single account to clandes via AccountService.RegisterAccount.
func registerAccountToClandes(ctx context.Context, svc proto.AccountService, acc *Account) error {
	accountType := mapAccountTypeToCapnp(acc)
	if accountType == proto.AccountType_unknown {
		return nil // not a supported type, skip
	}

	fut, rel := svc.RegisterAccount(ctx, func(p proto.AccountService_registerAccount_Params) error {
		if err := p.SetAccountId(strconv.FormatInt(acc.ID, 10)); err != nil {
			return err
		}
		p.SetAccountType(accountType)
		if err := p.SetVersion(""); err != nil { // empty = clandes picks default
			return err
		}
		if acc.Proxy != nil {
			if err := p.SetProxyUrl(buildProxyURL(acc.Proxy)); err != nil {
				return err
			}
		}

		// NewCredentials allocates the creds struct in the right segment
		creds, err := p.NewCredentials()
		if err != nil {
			return err
		}
		return setAccountCredentials(creds, acc)
	})
	defer rel()

	res, err := fut.Struct()
	if err != nil {
		return fmt.Errorf("RegisterAccount RPC: %w", err)
	}
	if !res.Success() {
		msg, _ := res.Message_()
		return fmt.Errorf("RegisterAccount: %s", msg)
	}
	return nil
}

// RemoveAccountFromClandes removes an account from clandes when it is deleted in sub2api.
func RemoveAccountFromClandes(ctx context.Context, client *ClandesClient, accountID int64) error {
	svc, err := client.AccountService()
	if err != nil {
		return fmt.Errorf("clandes remove account: get AccountService: %w", err)
	}
	defer svc.Release()

	fut, rel := svc.RemoveAccount(ctx, func(p proto.AccountService_removeAccount_Params) error {
		return p.SetAccountId(strconv.FormatInt(accountID, 10))
	})
	defer rel()

	res, err := fut.Struct()
	if err != nil {
		return fmt.Errorf("RemoveAccount RPC: %w", err)
	}
	if !res.Success() {
		msg, _ := res.Message_()
		return fmt.Errorf("RemoveAccount: %s", msg)
	}
	return nil
}

// --- helpers ---

func mapAccountTypeToCapnp(acc *Account) proto.AccountType {
	if acc.Platform != PlatformAnthropic {
		return proto.AccountType_unknown
	}
	switch acc.Type {
	case AccountTypeOAuth, AccountTypeSetupToken:
		return proto.AccountType_claudeSubscription
	case AccountTypeAPIKey:
		return proto.AccountType_claudePayAsYouGo
	default:
		return proto.AccountType_unknown
	}
}

func setAccountCredentials(creds proto.AccountCredentials, acc *Account) error {
	seg := capnp.Struct(creds).Segment()
	switch acc.Type {
	case AccountTypeOAuth, AccountTypeSetupToken:
		accessToken := acc.GetCredential("access_token")
		refreshToken := acc.GetCredential("refresh_token")
		tokenCreds, err := proto.NewClaudeTokenCredentials(seg)
		if err != nil {
			return err
		}
		if err := tokenCreds.SetAccessToken(accessToken); err != nil {
			return err
		}
		if err := tokenCreds.SetRefreshToken(refreshToken); err != nil {
			return err
		}
		return creds.SetClaudeSubCreds(tokenCreds)

	case AccountTypeAPIKey:
		apiKey := acc.GetCredential("api_key")
		baseURL := acc.GetCredential("base_url")
		keyCreds, err := proto.NewClaudeApiKeyCredentials(seg)
		if err != nil {
			return err
		}
		if err := keyCreds.SetApiKey(apiKey); err != nil {
			return err
		}
		if err := keyCreds.SetBaseUrl(baseURL); err != nil {
			return err
		}
		return creds.SetClaudeApiKeyCreds(keyCreds)
	}
	return nil
}

func buildProxyURL(proxy *Proxy) string {
	if proxy == nil {
		return ""
	}
	scheme := proxy.Protocol
	if scheme == "" {
		scheme = "http"
	}
	if proxy.Username != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%d", scheme, proxy.Username, proxy.Password, proxy.Host, proxy.Port)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, proxy.Host, proxy.Port)
}
