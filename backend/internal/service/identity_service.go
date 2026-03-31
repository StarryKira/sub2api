package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// 预编译正则表达式（避免每次调用重新编译）
var (
	// 匹配 User-Agent 版本号: xxx/x.y.z
	userAgentVersionRegex = regexp.MustCompile(`/(\d+)\.(\d+)\.(\d+)`)
)

// AccountExtraUpdater 用于将 device_id 和指纹 profile 持久化到 Account.Extra。
// 由 AccountRepository 实现。
type AccountExtraUpdater interface {
	UpdateExtra(ctx context.Context, accountID int64, updates map[string]any) error
}

// Fingerprint represents account fingerprint data
type Fingerprint struct {
	ClientID                string
	UserAgent               string
	StainlessLang           string
	StainlessPackageVersion string
	StainlessOS             string
	StainlessArch           string
	StainlessRuntime        string
	StainlessRuntimeVersion string
	UpdatedAt               int64 `json:",omitempty"` // Unix timestamp，用于判断是否需要续期TTL
}

// IdentityCache defines cache operations for identity service
type IdentityCache interface {
	GetFingerprint(ctx context.Context, accountID int64) (*Fingerprint, error)
	SetFingerprint(ctx context.Context, accountID int64, fp *Fingerprint) error
	// GetMaskedSessionID 获取固定的会话ID（用于会话ID伪装功能）
	// 返回的 sessionID 是一个 UUID 格式的字符串
	// 如果不存在或已过期（15分钟无请求），返回空字符串
	GetMaskedSessionID(ctx context.Context, accountID int64) (string, error)
	// SetMaskedSessionID 设置固定的会话ID，TTL 为 15 分钟
	// 每次调用都会刷新 TTL
	SetMaskedSessionID(ctx context.Context, accountID int64, sessionID string) error
}

// IdentityService 管理OAuth账号的请求身份指纹
type IdentityService struct {
	cache        IdentityCache
	extraUpdater AccountExtraUpdater
}

// NewIdentityService 创建新的IdentityService
func NewIdentityService(cache IdentityCache, extraUpdater AccountExtraUpdater) *IdentityService {
	return &IdentityService{cache: cache, extraUpdater: extraUpdater}
}

// GetOrCreateFingerprint 获取或创建账号的指纹。
//
// 优先级：
//  1. Redis 缓存（热路径）
//  2. Account.Extra["device_id"]（持久化的 device_id）
//  3. 全新生成（并持久化到 DB + Redis）
//
// account 参数用于读取 Extra 中持久化的 device_id 和 fingerprint_profile_index。
// 如果 account 为 nil，行为与旧版本一致（仅依赖 Redis 缓存）。
//
// 返回值 isNewDevice 为 true 表示 device_id 是首次生成的，调用方应考虑执行启动探测。
func (s *IdentityService) GetOrCreateFingerprint(ctx context.Context, accountID int64, headers http.Header, account *Account) (fp *Fingerprint, isNewDevice bool, err error) {
	// 1. 尝试从 Redis 缓存获取
	cached, cacheErr := s.cache.GetFingerprint(ctx, accountID)
	if cacheErr == nil && cached != nil {
		needWrite := false

		clientUA := headers.Get("User-Agent")
		if clientUA != "" && isNewerVersion(clientUA, cached.UserAgent) {
			mergeHeadersIntoFingerprint(cached, headers)
			needWrite = true
			logger.LegacyPrintf("service.identity", "Updated fingerprint for account %d: %s (merge update)", accountID, clientUA)
		} else if time.Since(time.Unix(cached.UpdatedAt, 0)) > 24*time.Hour {
			needWrite = true
		}

		if needWrite {
			cached.UpdatedAt = time.Now().Unix()
			if err := s.cache.SetFingerprint(ctx, accountID, cached); err != nil {
				logger.LegacyPrintf("service.identity", "Warning: failed to refresh fingerprint for account %d: %v", accountID, err)
			}
		}
		return cached, false, nil
	}

	// 2. Redis 缓存 miss — 尝试从 Account.Extra 恢复持久化的 device_id
	var persistedDeviceID string
	var profileIndex int = -1
	if account != nil {
		persistedDeviceID = account.GetExtraString("device_id")
		if v, ok := account.Extra["fingerprint_profile_index"]; ok {
			switch n := v.(type) {
			case float64:
				profileIndex = int(n)
			case int:
				profileIndex = n
			case int64:
				profileIndex = int(n)
			}
		}
	}

	// 3. 创建指纹
	newFP, selectedProfileIndex := s.createFingerprintFromHeaders(headers, accountID, profileIndex)

	if persistedDeviceID != "" {
		newFP.ClientID = persistedDeviceID
		isNewDevice = false
		logger.LegacyPrintf("service.identity", "Restored device_id from DB for account %d: %s", accountID, persistedDeviceID[:min(16, len(persistedDeviceID))]+"...")
	} else {
		newFP.ClientID = generateClientID()
		isNewDevice = true
		logger.LegacyPrintf("service.identity", "Generated new device_id for account %d: %s", accountID, newFP.ClientID[:min(16, len(newFP.ClientID))]+"...")

		s.persistDeviceID(ctx, accountID, newFP.ClientID, selectedProfileIndex, account)
	}

	newFP.UpdatedAt = time.Now().Unix()

	// 写回 Redis 缓存
	if err := s.cache.SetFingerprint(ctx, accountID, newFP); err != nil {
		logger.LegacyPrintf("service.identity", "Warning: failed to cache fingerprint for account %d: %v", accountID, err)
	}

	return newFP, isNewDevice, nil
}

// persistDeviceID 将 device_id 和 fingerprint_profile_index 持久化到 Account.Extra。
// profileIndex 来自 SelectProfileForAccount 的结果，用于锁定 profile 选择以防模板池变化。
func (s *IdentityService) persistDeviceID(ctx context.Context, accountID int64, deviceID string, profileIndex int, account *Account) {
	if s.extraUpdater == nil {
		return
	}

	updates := map[string]any{
		"device_id": deviceID,
	}

	if account == nil || account.Extra == nil || account.Extra["fingerprint_profile_index"] == nil {
		updates["fingerprint_profile_index"] = profileIndex
	}

	if err := s.extraUpdater.UpdateExtra(ctx, accountID, updates); err != nil {
		logger.LegacyPrintf("service.identity", "Warning: failed to persist device_id for account %d: %v", accountID, err)
	}
}

// createFingerprintFromHeaders 从请求头创建指纹。
// 当客户端 headers 缺失时（mimic 场景），使用基于 accountID 选择的多样化 profile。
// profileIndex >= 0 时使用持久化的 profile 索引，否则由 hash(accountID) 确定。
// createFingerprintFromHeaders 从请求头创建指纹，返回指纹和选中的 profile index。
func (s *IdentityService) createFingerprintFromHeaders(headers http.Header, accountID int64, profileIndex int) (*Fingerprint, int) {
	sel := claude.SelectProfileForAccount(accountID, profileIndex)

	fp := &Fingerprint{}

	if ua := headers.Get("User-Agent"); ua != "" {
		fp.UserAgent = ua
	} else {
		fp.UserAgent = sel.UserAgent
	}

	fp.StainlessLang = getHeaderOrDefault(headers, "X-Stainless-Lang", "js")
	fp.StainlessPackageVersion = getHeaderOrDefault(headers, "X-Stainless-Package-Version", sel.PackageVersion)
	fp.StainlessOS = getHeaderOrDefault(headers, "X-Stainless-OS", sel.Profile.OS)
	fp.StainlessArch = getHeaderOrDefault(headers, "X-Stainless-Arch", sel.Profile.Arch)
	fp.StainlessRuntime = getHeaderOrDefault(headers, "X-Stainless-Runtime", sel.Profile.Runtime)
	fp.StainlessRuntimeVersion = getHeaderOrDefault(headers, "X-Stainless-Runtime-Version", sel.RuntimeVersion)

	return fp, sel.ProfileIndex
}

// mergeHeadersIntoFingerprint 将请求头中实际存在的字段合并到现有指纹中（用于版本升级场景）
// 关键语义：请求中有的字段 → 用新值覆盖；缺失的头 → 保留缓存中的已有值
// 与 createFingerprintFromHeaders 的区别：后者用于首次创建，缺失头回退到 defaultFingerprint；
// 本函数用于升级更新，缺失头保留缓存值，避免将已知的真实值退化为硬编码默认值
func mergeHeadersIntoFingerprint(fp *Fingerprint, headers http.Header) {
	// User-Agent：版本升级的触发条件，一定存在
	if ua := headers.Get("User-Agent"); ua != "" {
		fp.UserAgent = ua
	}
	// X-Stainless-* 头：仅在请求中实际携带时才更新，否则保留缓存值
	mergeHeader(headers, "X-Stainless-Lang", &fp.StainlessLang)
	mergeHeader(headers, "X-Stainless-Package-Version", &fp.StainlessPackageVersion)
	mergeHeader(headers, "X-Stainless-OS", &fp.StainlessOS)
	mergeHeader(headers, "X-Stainless-Arch", &fp.StainlessArch)
	mergeHeader(headers, "X-Stainless-Runtime", &fp.StainlessRuntime)
	mergeHeader(headers, "X-Stainless-Runtime-Version", &fp.StainlessRuntimeVersion)
}

// mergeHeader 如果请求头中存在该字段则更新目标值，否则保留原值
func mergeHeader(headers http.Header, key string, target *string) {
	if v := headers.Get(key); v != "" {
		*target = v
	}
}

// getHeaderOrDefault 获取header值，如果不存在则返回默认值
func getHeaderOrDefault(headers http.Header, key, defaultValue string) string {
	if v := headers.Get(key); v != "" {
		return v
	}
	return defaultValue
}

// ApplyFingerprint 将指纹应用到请求头（覆盖原有的x-stainless-*头）
// 使用 setHeaderRaw 保持原始大小写（如 X-Stainless-OS 而非 X-Stainless-Os）
func (s *IdentityService) ApplyFingerprint(req *http.Request, fp *Fingerprint) {
	if fp == nil {
		return
	}

	// 设置user-agent
	if fp.UserAgent != "" {
		setHeaderRaw(req.Header, "User-Agent", fp.UserAgent)
	}

	// 设置x-stainless-*头（保持与 claude.DefaultHeaders 一致的大小写）
	if fp.StainlessLang != "" {
		setHeaderRaw(req.Header, "X-Stainless-Lang", fp.StainlessLang)
	}
	if fp.StainlessPackageVersion != "" {
		setHeaderRaw(req.Header, "X-Stainless-Package-Version", fp.StainlessPackageVersion)
	}
	if fp.StainlessOS != "" {
		setHeaderRaw(req.Header, "X-Stainless-OS", fp.StainlessOS)
	}
	if fp.StainlessArch != "" {
		setHeaderRaw(req.Header, "X-Stainless-Arch", fp.StainlessArch)
	}
	if fp.StainlessRuntime != "" {
		setHeaderRaw(req.Header, "X-Stainless-Runtime", fp.StainlessRuntime)
	}
	if fp.StainlessRuntimeVersion != "" {
		setHeaderRaw(req.Header, "X-Stainless-Runtime-Version", fp.StainlessRuntimeVersion)
	}
}

// RewriteUserID 重写body中的metadata.user_id
// 支持旧拼接格式和新 JSON 格式的 user_id 解析，
// 根据 fingerprintUA 版本选择输出格式。
//
// 重要：此函数使用 json.RawMessage 保留其他字段的原始字节，
// 避免重新序列化导致 thinking 块等内容被修改。
func (s *IdentityService) RewriteUserID(body []byte, accountID int64, accountUUID, cachedClientID, fingerprintUA string) ([]byte, error) {
	if len(body) == 0 || accountUUID == "" || cachedClientID == "" {
		return body, nil
	}

	metadata := gjson.GetBytes(body, "metadata")
	if !metadata.Exists() || metadata.Type == gjson.Null {
		return body, nil
	}
	if !strings.HasPrefix(strings.TrimSpace(metadata.Raw), "{") {
		return body, nil
	}

	userIDResult := metadata.Get("user_id")
	if !userIDResult.Exists() || userIDResult.Type != gjson.String {
		return body, nil
	}
	userID := userIDResult.String()
	if userID == "" {
		return body, nil
	}

	// 解析 user_id（兼容旧拼接格式和新 JSON 格式）
	parsed := ParseMetadataUserID(userID)
	if parsed == nil {
		return body, nil
	}

	sessionTail := parsed.SessionID // 原始session UUID

	// 生成新的session hash: SHA256(accountID::sessionTail) -> UUID格式
	seed := fmt.Sprintf("%d::%s", accountID, sessionTail)
	newSessionHash := generateUUIDFromSeed(seed)

	// 根据客户端版本选择输出格式
	version := ExtractCLIVersion(fingerprintUA)
	newUserID := FormatMetadataUserID(cachedClientID, accountUUID, newSessionHash, version)
	if newUserID == userID {
		return body, nil
	}

	newBody, err := sjson.SetBytes(body, "metadata.user_id", newUserID)
	if err != nil {
		return body, nil
	}
	return newBody, nil
}

// RewriteUserIDWithMasking 重写body中的metadata.user_id，支持会话ID伪装
// 如果账号启用了会话ID伪装（session_id_masking_enabled），
// 则在完成常规重写后，将 session 部分替换为固定的伪装ID（15分钟内保持不变）
//
// 重要：此函数使用 json.RawMessage 保留其他字段的原始字节，
// 避免重新序列化导致 thinking 块等内容被修改。
func (s *IdentityService) RewriteUserIDWithMasking(ctx context.Context, body []byte, account *Account, accountUUID, cachedClientID, fingerprintUA string) ([]byte, error) {
	// 先执行常规的 RewriteUserID 逻辑
	newBody, err := s.RewriteUserID(body, account.ID, accountUUID, cachedClientID, fingerprintUA)
	if err != nil {
		return newBody, err
	}

	// 检查是否启用会话ID伪装
	if !account.IsSessionIDMaskingEnabled() {
		return newBody, nil
	}

	metadata := gjson.GetBytes(newBody, "metadata")
	if !metadata.Exists() || metadata.Type == gjson.Null {
		return newBody, nil
	}
	if !strings.HasPrefix(strings.TrimSpace(metadata.Raw), "{") {
		return newBody, nil
	}

	userIDResult := metadata.Get("user_id")
	if !userIDResult.Exists() || userIDResult.Type != gjson.String {
		return newBody, nil
	}
	userID := userIDResult.String()
	if userID == "" {
		return newBody, nil
	}

	// 解析已重写的 user_id
	uidParsed := ParseMetadataUserID(userID)
	if uidParsed == nil {
		return newBody, nil
	}

	// 获取或生成固定的伪装 session ID
	maskedSessionID, err := s.cache.GetMaskedSessionID(ctx, account.ID)
	if err != nil {
		logger.LegacyPrintf("service.identity", "Warning: failed to get masked session ID for account %d: %v", account.ID, err)
		return newBody, nil
	}

	if maskedSessionID == "" {
		// 首次或已过期，生成新的伪装 session ID
		maskedSessionID = generateRandomUUID()
		logger.LegacyPrintf("service.identity", "Generated new masked session ID for account %d: %s", account.ID, maskedSessionID)
	}

	// 刷新 TTL（每次请求都刷新，保持 15 分钟有效期）
	if err := s.cache.SetMaskedSessionID(ctx, account.ID, maskedSessionID); err != nil {
		logger.LegacyPrintf("service.identity", "Warning: failed to set masked session ID for account %d: %v", account.ID, err)
	}

	// 用 FormatMetadataUserID 重建（保持与 RewriteUserID 相同的格式）
	version := ExtractCLIVersion(fingerprintUA)
	newUserID := FormatMetadataUserID(uidParsed.DeviceID, uidParsed.AccountUUID, maskedSessionID, version)

	slog.Debug("session_id_masking_applied",
		"account_id", account.ID,
		"before", userID,
		"after", newUserID,
	)

	if newUserID == userID {
		return newBody, nil
	}

	maskedBody, setErr := sjson.SetBytes(newBody, "metadata.user_id", newUserID)
	if setErr != nil {
		return newBody, nil
	}
	return maskedBody, nil
}

// generateRandomUUID 生成随机 UUID v4 格式字符串
func generateRandomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// fallback: 使用时间戳生成
		h := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		b = h[:16]
	}

	// 设置 UUID v4 版本和变体位
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// generateClientID 生成64位十六进制客户端ID（32字节随机数）
func generateClientID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// 极罕见的情况，使用时间戳+固定值作为fallback
		logger.LegacyPrintf("service.identity", "Warning: crypto/rand.Read failed: %v, using fallback", err)
		// 使用SHA256(当前纳秒时间)作为fallback
		h := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		return hex.EncodeToString(h[:])
	}
	return hex.EncodeToString(b)
}

// generateUUIDFromSeed 从种子生成确定性UUID v4格式字符串
func generateUUIDFromSeed(seed string) string {
	hash := sha256.Sum256([]byte(seed))
	bytes := hash[:16]

	// 设置UUID v4版本和变体位
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

// parseUserAgentVersion 解析user-agent版本号
// 例如：claude-cli/2.1.2 -> (2, 1, 2)
func parseUserAgentVersion(ua string) (major, minor, patch int, ok bool) {
	// 匹配 xxx/x.y.z 格式
	matches := userAgentVersionRegex.FindStringSubmatch(ua)
	if len(matches) != 4 {
		return 0, 0, 0, false
	}
	major, _ = strconv.Atoi(matches[1])
	minor, _ = strconv.Atoi(matches[2])
	patch, _ = strconv.Atoi(matches[3])
	return major, minor, patch, true
}

// extractProduct 提取 User-Agent 中 "/" 前的产品名
// 例如：claude-cli/2.1.22 (external, cli) -> "claude-cli"
func extractProduct(ua string) string {
	if idx := strings.Index(ua, "/"); idx > 0 {
		return strings.ToLower(ua[:idx])
	}
	return ""
}

// isNewerVersion 比较版本号，判断newUA是否比cachedUA更新
// 要求产品名一致（防止浏览器 UA 如 Mozilla/5.0 误判为更新版本）
func isNewerVersion(newUA, cachedUA string) bool {
	// 校验产品名一致性
	newProduct := extractProduct(newUA)
	cachedProduct := extractProduct(cachedUA)
	if newProduct == "" || cachedProduct == "" || newProduct != cachedProduct {
		return false
	}

	newMajor, newMinor, newPatch, newOk := parseUserAgentVersion(newUA)
	cachedMajor, cachedMinor, cachedPatch, cachedOk := parseUserAgentVersion(cachedUA)

	if !newOk || !cachedOk {
		return false
	}

	// 比较版本号
	if newMajor > cachedMajor {
		return true
	}
	if newMajor < cachedMajor {
		return false
	}

	if newMinor > cachedMinor {
		return true
	}
	if newMinor < cachedMinor {
		return false
	}

	return newPatch > cachedPatch
}

