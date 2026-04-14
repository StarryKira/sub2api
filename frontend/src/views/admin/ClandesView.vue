<template>
  <AppLayout>
    <div class="mx-auto max-w-3xl space-y-6">
      <!-- Header -->
      <div>
        <h1 class="text-xl font-semibold text-gray-900 dark:text-white">{{ t('admin.clandes.title') }}</h1>
        <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">{{ t('admin.clandes.description') }}</p>
      </div>

      <!-- Loading state -->
      <div v-if="loading && !status" class="flex items-center justify-center py-12">
        <div class="h-8 w-8 animate-spin rounded-full border-b-2 border-primary-600"></div>
      </div>

      <!-- Status Card -->
      <div v-else-if="status" class="card p-6">
        <div class="mb-5 flex items-center justify-between">
          <h3 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('admin.clandes.status') }}</h3>
          <button type="button" class="btn btn-secondary btn-sm" :disabled="loading" @click="fetchStatus">
            <svg class="h-4 w-4" :class="{ 'animate-spin': loading }" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </div>

        <dl class="space-y-4">
          <div class="flex items-center justify-between">
            <dt class="text-sm text-gray-600 dark:text-gray-400">{{ t('admin.clandes.integration') }}</dt>
            <dd>
              <span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium" :class="status.enabled ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'">
                {{ status.enabled ? t('admin.clandes.enabled') : t('admin.clandes.disabled') }}
              </span>
            </dd>
          </div>
          <div v-if="status.enabled" class="flex items-center justify-between">
            <dt class="text-sm text-gray-600 dark:text-gray-400">{{ t('admin.clandes.connection') }}</dt>
            <dd>
              <span class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium" :class="status.connected ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'">
                <span class="h-1.5 w-1.5 rounded-full" :class="status.connected ? 'bg-green-500' : 'bg-red-500'" />
                {{ status.connected ? t('admin.clandes.connected') : t('admin.clandes.disconnected') }}
              </span>
            </dd>
          </div>
          <div v-if="status.enabled && status.addr" class="flex items-center justify-between">
            <dt class="text-sm text-gray-600 dark:text-gray-400">{{ t('admin.clandes.addr') }}</dt>
            <dd class="font-mono text-sm text-gray-900 dark:text-white">{{ status.addr }}</dd>
          </div>
        </dl>

        <div v-if="!status.enabled" class="mt-5 rounded-lg bg-amber-50 p-4 text-sm text-amber-700 dark:bg-amber-900/20 dark:text-amber-400">
          {{ t('admin.clandes.notEnabled') }}
        </div>
      </div>

      <!-- Error state -->
      <div v-else class="card p-6 text-center text-sm text-red-600 dark:text-red-400">
        {{ t('admin.clandes.loadError') }}
        <button type="button" class="ml-2 underline" @click="fetchStatus">{{ t('common.refresh') }}</button>
      </div>

      <!-- Accounts Card -->
      <div class="card p-6">
        <div class="mb-5 flex items-center justify-between">
          <h3 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('admin.clandes.accounts') }}</h3>
          <div class="flex gap-2">
            <button type="button" class="btn btn-secondary btn-sm" :disabled="syncing || !status?.connected" @click="doSync">
              {{ syncing ? t('common.loading') : t('admin.clandes.syncAccounts') }}
            </button>
            <button type="button" class="btn btn-primary btn-sm" @click="showCreateDialog = true">
              {{ t('admin.clandes.addAccount') }}
            </button>
          </div>
        </div>

        <!-- Account list -->
        <div v-if="accountsLoading" class="flex items-center justify-center py-8">
          <div class="h-6 w-6 animate-spin rounded-full border-b-2 border-primary-600"></div>
        </div>
        <div v-else-if="!accounts || accounts.length === 0" class="py-8 text-center text-sm text-gray-500 dark:text-gray-400">
          {{ t('admin.clandes.noAccounts') }}
        </div>
        <div v-else class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-gray-200 text-left text-xs font-medium text-gray-500 dark:border-gray-700 dark:text-gray-400">
                <th class="px-3 py-2">ID</th>
                <th class="px-3 py-2">{{ t('admin.clandes.accountName') }}</th>
                <th class="px-3 py-2">{{ t('admin.clandes.accountType') }}</th>
                <th class="px-3 py-2">{{ t('common.status') }}</th>
                <th class="px-3 py-2">{{ t('common.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="acc in accounts" :key="acc.id" class="border-b border-gray-100 dark:border-gray-800">
                <td class="px-3 py-2 text-gray-600 dark:text-gray-400">{{ acc.id }}</td>
                <td class="px-3 py-2 text-gray-900 dark:text-white">{{ acc.name }}</td>
                <td class="px-3 py-2">
                  <span class="rounded bg-gray-100 px-1.5 py-0.5 text-xs dark:bg-gray-800">{{ acc.type }}</span>
                </td>
                <td class="px-3 py-2">
                  <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium" :class="acc.status === 'active' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'">
                    {{ acc.status }}
                  </span>
                </td>
                <td class="px-3 py-2">
                  <button type="button" class="text-xs text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300" :disabled="deleting === acc.id" @click="doDelete(acc.id)">
                    {{ deleting === acc.id ? t('common.loading') : t('common.delete') }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Create account dialog -->
    <!-- Add account dialog -->
    <teleport to="body">
      <transition name="modal">
        <div v-if="showCreateDialog" class="fixed inset-0 z-50 flex items-center justify-center p-4" @mousedown.self="showCreateDialog = false">
          <div class="fixed inset-0 bg-black/50" @click="showCreateDialog = false"></div>
          <div class="relative w-full max-w-md rounded-xl bg-white p-6 shadow-2xl dark:bg-dark-800">
            <h2 class="mb-4 text-lg font-bold text-gray-900 dark:text-white">{{ t('admin.clandes.addAccount') }}</h2>

            <!-- Method selection -->
            <div class="mb-4 flex gap-2">
              <button type="button" class="btn btn-sm" :class="addMethod === 'oauth' ? 'btn-primary' : 'btn-secondary'" @click="addMethod = 'oauth'">
                OAuth {{ t('admin.clandes.login') }}
              </button>
              <button type="button" class="btn btn-sm" :class="addMethod === 'apikey' ? 'btn-primary' : 'btn-secondary'" @click="addMethod = 'apikey'">
                API Key
              </button>
            </div>

            <!-- OAuth login -->
            <div v-if="addMethod === 'oauth'" class="space-y-4">
              <p class="text-sm text-gray-600 dark:text-gray-400">{{ t('admin.clandes.oauthHint') }}</p>
              <button type="button" class="btn btn-primary w-full" :disabled="oauthStarting" @click="doStartOAuth">
                {{ oauthStarting ? t('common.loading') : t('admin.clandes.startOAuth') }}
              </button>
              <!-- OAuth URL + code input (shown after getting URL) -->
              <div v-if="oauthSessionId" class="space-y-3">
                <div>
                  <label class="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">{{ t('admin.clandes.oauthUrlHint') }}</label>
                  <div class="flex gap-2">
                    <input :value="oauthUrl" class="input w-full font-mono text-xs" readonly @click="($event.target as HTMLInputElement)?.select()" />
                    <button type="button" class="btn btn-secondary btn-sm shrink-0" @click="copyUrl">
                      {{ urlCopied ? t('admin.clandes.copied') : 'Copy' }}
                    </button>
                  </div>
                </div>
                <div>
                  <label class="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">{{ t('admin.clandes.oauthCodeHint') }}</label>
                  <input v-model="oauthCode" class="input w-full" :placeholder="t('admin.clandes.oauthCodePlaceholder')" />
                </div>
                <button type="button" class="btn btn-primary btn-sm w-full" :disabled="!oauthCode || oauthCompleting" @click="doCompleteOAuth">
                  {{ oauthCompleting ? t('common.loading') : t('admin.clandes.completeOAuth') }}
                </button>
              </div>
            </div>

            <!-- API Key form -->
            <form v-else class="space-y-4" @submit.prevent="doCreate">
              <div>
                <label class="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">{{ t('admin.clandes.accountName') }}</label>
                <input v-model="createForm.name" class="input w-full" required />
              </div>
              <div>
                <label class="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">API Key</label>
                <input v-model="createForm.apiKey" class="input w-full" required />
              </div>
              <div>
                <label class="mb-1 block text-xs font-medium text-gray-600 dark:text-gray-400">Base URL</label>
                <input v-model="createForm.baseUrl" class="input w-full" placeholder="https://api.anthropic.com" />
              </div>
              <div class="flex justify-end gap-2 pt-2">
                <button type="button" class="btn btn-secondary btn-sm" @click="showCreateDialog = false">{{ t('common.cancel') }}</button>
                <button type="submit" class="btn btn-primary btn-sm" :disabled="creating">
                  {{ creating ? t('common.loading') : t('common.create') }}
                </button>
              </div>
            </form>

            <div class="mt-4 flex justify-end">
              <button type="button" class="text-xs text-gray-400 hover:text-gray-600 dark:hover:text-gray-300" @click="showCreateDialog = false">{{ t('common.close') }}</button>
            </div>
          </div>
        </div>
      </transition>
    </teleport>
  </AppLayout>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import { adminAPI } from '@/api'
import { useAppStore } from '@/stores'
import type { ClandesStatus, ClandesAccount, CreateClandesAccountRequest } from '@/api/admin/clandes'

const { t } = useI18n()
const appStore = useAppStore()

const status = ref<ClandesStatus | null>(null)
const loading = ref(false)
const syncing = ref(false)
const accounts = ref<ClandesAccount[]>([])
const accountsLoading = ref(false)
const showCreateDialog = ref(false)
const creating = ref(false)
const deleting = ref<number | null>(null)
const addMethod = ref<'oauth' | 'apikey'>('oauth')
const oauthStarting = ref(false)
const oauthSessionId = ref('')
const oauthUrl = ref('')
const oauthCode = ref('')
const oauthCompleting = ref(false)
const urlCopied = ref(false)

const createForm = ref({
  name: '',
  apiKey: '',
  baseUrl: '',
})

let refreshTimer: ReturnType<typeof setInterval> | null = null

async function fetchStatus() {
  loading.value = true
  try {
    status.value = await adminAPI.clandes.getStatus()
  } catch (e) {
    status.value = null
    appStore.showError((e as { message?: string })?.message ?? t('admin.clandes.loadError'))
  } finally {
    loading.value = false
  }
}

async function fetchAccounts() {
  accountsLoading.value = true
  try {
    accounts.value = await adminAPI.clandes.listAccounts()
  } catch (e) {
    appStore.showError((e as { message?: string })?.message ?? t('admin.clandes.loadError'))
  } finally {
    accountsLoading.value = false
  }
}

async function doSync() {
  syncing.value = true
  try {
    await adminAPI.clandes.syncAccounts()
    appStore.showSuccess(t('admin.clandes.syncSuccess'))
  } catch (e) {
    appStore.showError((e as { message?: string })?.message ?? t('admin.clandes.syncFailed'))
  } finally {
    syncing.value = false
  }
}

async function doStartOAuth() {
  oauthStarting.value = true
  try {
    const redirectUri = window.location.origin + '/admin/clandes'
    const result = await adminAPI.clandes.startOAuth(redirectUri)
    oauthSessionId.value = result.session_id
    oauthUrl.value = result.auth_url
  } catch (e) {
    appStore.showError((e as { message?: string })?.message ?? t('admin.clandes.oauthFailed'))
  } finally {
    oauthStarting.value = false
  }
}

async function copyUrl() {
  try {
    await navigator.clipboard.writeText(oauthUrl.value)
    urlCopied.value = true
    setTimeout(() => { urlCopied.value = false }, 2000)
  } catch {
    appStore.showError('Failed to copy')
  }
}

async function doCompleteOAuth() {
  oauthCompleting.value = true
  try {
    const callbackUrl = window.location.origin + '/admin/clandes'
    await adminAPI.clandes.completeOAuth(oauthSessionId.value, oauthCode.value, callbackUrl)
    appStore.showSuccess(t('admin.clandes.createSuccess'))
    showCreateDialog.value = false
    oauthSessionId.value = ''
    oauthCode.value = ''
    await fetchAccounts()
  } catch (e) {
    appStore.showError((e as { message?: string })?.message ?? t('admin.clandes.oauthFailed'))
  } finally {
    oauthCompleting.value = false
  }
}

async function doCreate() {
  creating.value = true
  try {
    const f = createForm.value
    const req: CreateClandesAccountRequest = {
      name: f.name,
      type: 'apikey',
      credentials: { api_key: f.apiKey, base_url: f.baseUrl || undefined },
    }
    await adminAPI.clandes.createAccount(req)
    appStore.showSuccess(t('admin.clandes.createSuccess'))
    showCreateDialog.value = false
    resetForm()
    await fetchAccounts()
  } catch (e) {
    appStore.showError((e as { message?: string })?.message ?? t('admin.clandes.createFailed'))
  } finally {
    creating.value = false
  }
}

async function doDelete(id: number) {
  deleting.value = id
  try {
    await adminAPI.clandes.deleteAccount(id)
    appStore.showSuccess(t('admin.clandes.deleteSuccess'))
    await fetchAccounts()
  } catch (e) {
    appStore.showError((e as { message?: string })?.message ?? t('admin.clandes.deleteFailed'))
  } finally {
    deleting.value = null
  }
}

function resetForm() {
  createForm.value = { name: '', apiKey: '', baseUrl: '' }
  addMethod.value = 'oauth'
  oauthSessionId.value = ''
  oauthUrl.value = ''
  oauthCode.value = ''
  urlCopied.value = false
}

onMounted(() => {
  fetchStatus()
  fetchAccounts()
  refreshTimer = setInterval(fetchStatus, 30_000)
})

onBeforeUnmount(() => {
  if (refreshTimer !== null) {
    clearInterval(refreshTimer)
  }
})
</script>
