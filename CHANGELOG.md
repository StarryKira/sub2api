
# Changelog

所有重要变更都记录在此文件中，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)。

---

## [未发布]

### 新增

- **管理员手动重置订阅配额**：新增 `POST /api/v1/admin/subscriptions/:id/reset-quota` 接口，允许管理员将指定订阅的每日和/或每周用量窗口归零并从今天重新计算。前端订阅列表新增"重置配额"按钮（仅对 active 状态订阅显示），点击后弹出确认对话框，操作期间按钮自动禁用防止重复提交。

---

## 近期变更（来自 PR 合并记录）

### 新增

- **批量重置账号状态 & 批量刷新令牌**：支持在账号管理页面批量操作，减少逐条操作的繁琐步骤。
- **导入账号时提取用户信息**：从 `id_token` 中 best-effort 解析用户信息，减少手动填写量。
- **OpenAI JWT 展示 chatgpt_plan_type**：导入 OpenAI 账号时自动从 JWT 提取套餐类型并在前端展示。
- **启动时清理过期并发槽**：服务启动时自动清除遗留的僵尸并发占用，避免重启后额度被虚占。
- **iframe 嵌入页面透传 locale**：通过 `lang` 参数将当前语言设置传递给 iframe 内嵌页面，保持语言一致。

### 修复

- **Pool 模式同账号重试**：OpenAI 临时性 400 错误现可在池模式下对同一账号发起重试，而不是直接失败。
- **OpenAI Responses SSE 扫描行长限制**：统一使用共享配置中的 `max_line_size`，修复超长行被截断的问题。
- **配额角标垂直排列**：修复管理后台容量列中多个配额角标的布局错位问题。
- **LinuxDo OAuth 邀请码校验**：修复 LinuxDo OAuth 登录在需要邀请码时的流程异常。
- **gpt→claude 同步请求返回 SSE 的 bug**：修复将 GPT 请求转发给 Claude 时，同步请求错误地以 SSE 格式响应的问题。
