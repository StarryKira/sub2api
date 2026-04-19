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
  syncAccounts,
  startOAuth,
  exchangeOAuth
}

export default clandesAPI
