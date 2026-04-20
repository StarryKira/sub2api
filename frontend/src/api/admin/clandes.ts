/**
 * Clandes integration API endpoints
 */

import { apiClient } from '../client'

export interface ClandesStatus {
  enabled: boolean
  connected: boolean
  addr: string
  version?: string
}

export async function getStatus(): Promise<ClandesStatus> {
  const { data } = await apiClient.get<ClandesStatus>('/admin/clandes/status')
  return data
}

export interface ClandesConfig {
  enabled: boolean
  addr: string
  auth_token_configured: boolean
  reconnect_interval: number
  config_file: string
}

export interface ClandesConfigUpdate {
  enabled: boolean
  addr: string
  // null = keep existing token; "" = clear
  auth_token: string | null
  reconnect_interval: number
}

export async function getConfig(): Promise<ClandesConfig> {
  const { data } = await apiClient.get<ClandesConfig>('/admin/clandes/config')
  return data
}

export async function updateConfig(
  payload: ClandesConfigUpdate
): Promise<{ message: string; config_file: string }> {
  const { data } = await apiClient.post<{ message: string; config_file: string }>(
    '/admin/clandes/config',
    payload
  )
  return data
}

export async function syncAccounts(): Promise<{ message: string }> {
  const { data } = await apiClient.post<{ message: string }>('/admin/clandes/sync')
  return data
}

export interface OAuthStartResponse {
  auth_url: string
  session_id: string
}

export interface OAuthExchangeResponse {
  access_token: string
  refresh_token: string
  expires_in: number
  email: string
  org_uuid: string
}

export async function startOAuth(
  redirectUri: string,
  proxyId?: number | null
): Promise<OAuthStartResponse> {
  const { data } = await apiClient.post<OAuthStartResponse>('/admin/clandes/oauth/start', {
    redirect_uri: redirectUri,
    ...(proxyId != null ? { proxy_id: proxyId } : {})
  })
  return data
}

export async function exchangeOAuth(
  sessionId: string,
  code: string,
  callbackUrl: string
): Promise<OAuthExchangeResponse> {
  const { data } = await apiClient.post<OAuthExchangeResponse>('/admin/clandes/oauth/exchange', {
    session_id: sessionId,
    code,
    callback_url: callbackUrl
  })
  return data
}

export const clandesAPI = {
  getStatus,
  getConfig,
  updateConfig,
  syncAccounts,
  startOAuth,
  exchangeOAuth
}

export default clandesAPI
