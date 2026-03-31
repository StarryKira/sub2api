// Package claude provides constants and helpers for Claude API integration.
package claude

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Claude Code 客户端相关常量

// Beta header 常量
const (
	BetaOAuth                    = "oauth-2025-04-20"
	BetaClaudeCode               = "claude-code-20250219"
	BetaInterleavedThinking      = "interleaved-thinking-2025-05-14"
	BetaFineGrainedToolStreaming = "fine-grained-tool-streaming-2025-05-14"
	BetaTokenCounting            = "token-counting-2024-11-01"
	BetaContext1M                = "context-1m-2025-08-07"
	BetaFastMode                 = "fast-mode-2026-02-01"
)

// DroppedBetas 是转发时需要从 anthropic-beta header 中移除的 beta token 列表。
// 这些 token 是客户端特有的，不应透传给上游 API。
var DroppedBetas = []string{}

// DefaultBetaHeader Claude Code 客户端默认的 anthropic-beta header
const DefaultBetaHeader = BetaClaudeCode + "," + BetaOAuth + "," + BetaInterleavedThinking + "," + BetaFineGrainedToolStreaming

// MessageBetaHeaderNoTools /v1/messages 在无工具时的 beta header
//
// NOTE: Claude Code OAuth credentials are scoped to Claude Code. When we "mimic"
// Claude Code for non-Claude-Code clients, we must include the claude-code beta
// even if the request doesn't use tools, otherwise upstream may reject the
// request as a non-Claude-Code API request.
const MessageBetaHeaderNoTools = BetaClaudeCode + "," + BetaOAuth + "," + BetaInterleavedThinking

// MessageBetaHeaderWithTools /v1/messages 在有工具时的 beta header
const MessageBetaHeaderWithTools = BetaClaudeCode + "," + BetaOAuth + "," + BetaInterleavedThinking

// CountTokensBetaHeader count_tokens 请求使用的 anthropic-beta header
const CountTokensBetaHeader = BetaClaudeCode + "," + BetaOAuth + "," + BetaInterleavedThinking + "," + BetaTokenCounting

// HaikuBetaHeader Haiku 模型使用的 anthropic-beta header（不需要 claude-code beta）
const HaikuBetaHeader = BetaOAuth + "," + BetaInterleavedThinking

// APIKeyBetaHeader API-key 账号建议使用的 anthropic-beta header（不包含 oauth）
const APIKeyBetaHeader = BetaClaudeCode + "," + BetaInterleavedThinking + "," + BetaFineGrainedToolStreaming

// APIKeyHaikuBetaHeader Haiku 模型在 API-key 账号下使用的 anthropic-beta header（不包含 oauth / claude-code）
const APIKeyHaikuBetaHeader = BetaInterleavedThinking

// DefaultCLIVersion 与 header_util.go 抓包来源（claude-cli/2.1.81）保持一致
const DefaultCLIVersion = "2.1.81"

// DefaultHeaders 是 Claude Code 客户端默认请求头。
// 注意：当启用了指纹系统时，这些值会被 ApplyFingerprint 覆盖。
// 此处作为最后的 fallback，使用最新版本。
var DefaultHeaders = map[string]string{
	// Keep these in sync with recent Claude CLI traffic to reduce the chance
	// that Claude Code-scoped OAuth credentials are rejected as "non-CLI" usage.
	"User-Agent":                                "claude-cli/" + DefaultCLIVersion + " (external, cli)",
	"X-Stainless-Lang":                          "js",
	"X-Stainless-Package-Version":               "0.72.1",
	"X-Stainless-OS":                            "MacOS",
	"X-Stainless-Arch":                          "arm64",
	"X-Stainless-Runtime":                       "node",
	"X-Stainless-Runtime-Version":               "v22.16.0",
	"X-Stainless-Retry-Count":                   "0",
	"X-Stainless-Timeout":                       "600",
	"X-App":                                     "cli",
	"Anthropic-Dangerous-Direct-Browser-Access": "true",
}

// FingerprintProfile 真实 Claude Code 客户端的指纹模板。
// 基于对真实 Claude CLI 流量的观察，覆盖常见的 OS/Arch/Runtime 组合。
type FingerprintProfile struct {
	OS              string   // X-Stainless-OS: "MacOS", "Linux", "Windows_NT"
	Arch            string   // X-Stainless-Arch: "arm64", "x64"
	Runtime         string   // X-Stainless-Runtime: "node"
	RuntimeVersions []string // 该平台常见的 node 版本
	PackageVersions []string // @anthropic-ai/sdk 版本
	CLIVersions     []string // claude-cli 版本
}

// RealisticProfiles 基于真实 Claude Code 用户环境的指纹模板池。
// 权重按真实用户分布：macOS arm64 最多，其次 Linux x64，再次 macOS x64 等。
var RealisticProfiles = []FingerprintProfile{
	{
		// macOS Apple Silicon — 最常见的 Claude Code 用户环境
		OS: "MacOS", Arch: "arm64", Runtime: "node",
		RuntimeVersions: []string{"v22.11.0", "v22.16.0", "v24.13.0"},
		PackageVersions: []string{"0.70.0", "0.72.1", "0.68.2"},
		CLIVersions:     []string{"2.1.81", "2.1.78", "2.2.0"},
	},
	{
		// macOS Intel — 老款 Mac 用户
		OS: "MacOS", Arch: "x64", Runtime: "node",
		RuntimeVersions: []string{"v22.11.0", "v22.16.0"},
		PackageVersions: []string{"0.70.0", "0.72.1"},
		CLIVersions:     []string{"2.1.81", "2.1.78"},
	},
	{
		// Linux x64 — 服务器/WSL/开发者
		OS: "Linux", Arch: "x64", Runtime: "node",
		RuntimeVersions: []string{"v22.11.0", "v22.16.0", "v24.13.0"},
		PackageVersions: []string{"0.70.0", "0.72.1", "0.68.2"},
		CLIVersions:     []string{"2.1.81", "2.1.78", "2.2.0"},
	},
	{
		// Linux arm64 — ARM 服务器/Raspberry Pi/Codespaces
		OS: "Linux", Arch: "arm64", Runtime: "node",
		RuntimeVersions: []string{"v22.16.0", "v24.13.0"},
		PackageVersions: []string{"0.70.0", "0.72.1"},
		CLIVersions:     []string{"2.1.81", "2.1.78"},
	},
	{
		// Windows x64 — Windows 用户
		OS: "Windows_NT", Arch: "x64", Runtime: "node",
		RuntimeVersions: []string{"v22.11.0", "v22.16.0"},
		PackageVersions: []string{"0.70.0", "0.72.1"},
		CLIVersions:     []string{"2.1.81", "2.1.78"},
	},
}

// SelectedFingerprint 从 SelectProfileForAccount 返回的完整指纹选择结果。
type SelectedFingerprint struct {
	ProfileIndex   int // 在 RealisticProfiles 中的索引，用于持久化
	Profile        FingerprintProfile
	CLIVersion     string
	PackageVersion string
	RuntimeVersion string
	UserAgent      string // 完整的 User-Agent 字符串
}

// SelectProfileForAccount 基于 accountID 确定性地选择一个完整的指纹组合。
// 同一个 accountID 永远返回相同的结果。如果提供了 lockedIndex >= 0，
// 则使用该索引选择 profile（用于已持久化的账号）。
func SelectProfileForAccount(accountID int64, lockedIndex int) SelectedFingerprint {
	h := sha256.Sum256([]byte(fmt.Sprintf("fingerprint:%d", accountID)))
	seed := binary.BigEndian.Uint64(h[:8])

	// 选择 profile
	profileIdx := int(seed % uint64(len(RealisticProfiles)))
	if lockedIndex >= 0 && lockedIndex < len(RealisticProfiles) {
		profileIdx = lockedIndex
	}
	profile := RealisticProfiles[profileIdx]

	// 确定性选择版本组合（使用不同的 hash 位段避免关联）
	seed2 := binary.BigEndian.Uint64(h[8:16])
	cliVersion := profile.CLIVersions[int(seed2%uint64(len(profile.CLIVersions)))]

	seed3 := binary.BigEndian.Uint64(h[16:24])
	pkgVersion := profile.PackageVersions[int(seed3%uint64(len(profile.PackageVersions)))]

	seed4 := binary.BigEndian.Uint64(h[24:32])
	rtVersion := profile.RuntimeVersions[int(seed4%uint64(len(profile.RuntimeVersions)))]

	return SelectedFingerprint{
		ProfileIndex:   profileIdx,
		Profile:        profile,
		CLIVersion:     cliVersion,
		PackageVersion: pkgVersion,
		RuntimeVersion: rtVersion,
		UserAgent:      fmt.Sprintf("claude-cli/%s (external, cli)", cliVersion),
	}
}

// Model 表示一个 Claude 模型
type Model struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`
}

// DefaultModels Claude Code 客户端支持的默认模型列表
var DefaultModels = []Model{
	{
		ID:          "claude-opus-4-5-20251101",
		Type:        "model",
		DisplayName: "Claude Opus 4.5",
		CreatedAt:   "2025-11-01T00:00:00Z",
	},
	{
		ID:          "claude-opus-4-6",
		Type:        "model",
		DisplayName: "Claude Opus 4.6",
		CreatedAt:   "2026-02-06T00:00:00Z",
	},
	{
		ID:          "claude-sonnet-4-6",
		Type:        "model",
		DisplayName: "Claude Sonnet 4.6",
		CreatedAt:   "2026-02-18T00:00:00Z",
	},
	{
		ID:          "claude-sonnet-4-5-20250929",
		Type:        "model",
		DisplayName: "Claude Sonnet 4.5",
		CreatedAt:   "2025-09-29T00:00:00Z",
	},
	{
		ID:          "claude-haiku-4-5-20251001",
		Type:        "model",
		DisplayName: "Claude Haiku 4.5",
		CreatedAt:   "2025-10-01T00:00:00Z",
	},
}

// DefaultModelIDs 返回默认模型的 ID 列表
func DefaultModelIDs() []string {
	ids := make([]string, len(DefaultModels))
	for i, m := range DefaultModels {
		ids[i] = m.ID
	}
	return ids
}

// DefaultTestModel 测试时使用的默认模型
const DefaultTestModel = "claude-sonnet-4-5-20250929"

// ModelIDOverrides Claude OAuth 请求需要的模型 ID 映射
var ModelIDOverrides = map[string]string{
	"claude-sonnet-4-5": "claude-sonnet-4-5-20250929",
	"claude-opus-4-5":   "claude-opus-4-5-20251101",
	"claude-haiku-4-5":  "claude-haiku-4-5-20251001",
}

// ModelIDReverseOverrides 用于将上游模型 ID 还原为短名
var ModelIDReverseOverrides = map[string]string{
	"claude-sonnet-4-5-20250929": "claude-sonnet-4-5",
	"claude-opus-4-5-20251101":   "claude-opus-4-5",
	"claude-haiku-4-5-20251001":  "claude-haiku-4-5",
}

// NormalizeModelID 根据 Claude OAuth 规则映射模型
func NormalizeModelID(id string) string {
	if id == "" {
		return id
	}
	if mapped, ok := ModelIDOverrides[id]; ok {
		return mapped
	}
	return id
}

// DenormalizeModelID 将上游模型 ID 转换为短名
func DenormalizeModelID(id string) string {
	if id == "" {
		return id
	}
	if mapped, ok := ModelIDReverseOverrides[id]; ok {
		return mapped
	}
	return id
}
