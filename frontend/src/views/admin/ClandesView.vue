<template>
  <AppLayout>
    <div class="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 class="text-xl font-semibold text-gray-900 dark:text-white">{{ t('admin.clandes.title') }}</h1>
        <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">{{ t('admin.clandes.description') }}</p>
      </div>

      <div v-if="loading && !status" class="flex items-center justify-center py-12">
        <div class="h-8 w-8 animate-spin rounded-full border-b-2 border-primary-600"></div>
      </div>

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
          <div v-if="status.enabled && status.version" class="flex items-center justify-between">
            <dt class="text-sm text-gray-600 dark:text-gray-400">{{ t('admin.clandes.version') }}</dt>
            <dd class="font-mono text-sm text-gray-900 dark:text-white">{{ status.version }}</dd>
          </div>
        </dl>

        <div v-if="status.enabled" class="mt-6">
          <button type="button" class="btn btn-primary btn-sm" :disabled="syncing || !status.connected" @click="doSync">
            {{ syncing ? t('common.loading') : t('admin.clandes.syncAccounts') }}
          </button>
          <span v-if="!status.connected" class="ml-2 text-xs text-gray-400 dark:text-gray-500">{{ t('admin.clandes.syncDisabledHint') }}</span>
        </div>
      </div>

      <div v-else class="card p-6 text-center text-sm text-red-600 dark:text-red-400">
        {{ t('admin.clandes.loadError') }}
        <button type="button" class="ml-2 underline" @click="fetchStatus">{{ t('common.refresh') }}</button>
      </div>

      <div v-if="config" class="card p-6">
        <h3 class="mb-1 text-base font-semibold text-gray-900 dark:text-white">{{ t('admin.clandes.configTitle') }}</h3>
        <p class="mb-5 text-xs text-gray-500 dark:text-gray-400">
          {{ t('admin.clandes.configDesc') }}
          <code v-if="config.config_file" class="ml-1 rounded bg-gray-100 px-1 py-0.5 font-mono text-[11px] dark:bg-gray-800">{{ config.config_file }}</code>
        </p>

        <form class="space-y-4" @submit.prevent="saveConfig">
          <label class="flex items-center gap-2">
            <input v-model="form.enabled" type="checkbox" class="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500" />
            <span class="text-sm text-gray-700 dark:text-gray-300">{{ t('admin.clandes.cfgEnabled') }}</span>
          </label>

          <div>
            <label class="mb-1 block text-sm text-gray-700 dark:text-gray-300">{{ t('admin.clandes.cfgAddr') }}</label>
            <input v-model="form.addr" type="text" placeholder="127.0.0.1:8082" class="input w-full" required />
          </div>

          <div>
            <label class="mb-1 block text-sm text-gray-700 dark:text-gray-300">
              {{ t('admin.clandes.cfgAuthToken') }}
              <span v-if="config.auth_token_configured && !tokenTouched" class="ml-2 text-xs text-gray-500">{{ t('admin.clandes.cfgAuthTokenSet') }}</span>
            </label>
            <input
              v-model="form.authToken"
              :type="showToken ? 'text' : 'password'"
              :placeholder="config.auth_token_configured ? t('admin.clandes.cfgAuthTokenKeep') : ''"
              class="input w-full font-mono"
              @input="tokenTouched = true"
            />
            <div class="mt-1 flex items-center gap-3 text-xs">
              <button type="button" class="text-primary-600 hover:underline" @click="showToken = !showToken">
                {{ showToken ? t('admin.clandes.cfgTokenHide') : t('admin.clandes.cfgTokenShow') }}
              </button>
              <button v-if="config.auth_token_configured" type="button" class="text-red-600 hover:underline" @click="clearToken">
                {{ t('admin.clandes.cfgTokenClear') }}
              </button>
            </div>
          </div>

          <div>
            <label class="mb-1 block text-sm text-gray-700 dark:text-gray-300">{{ t('admin.clandes.cfgReconnectInterval') }}</label>
            <input v-model.number="form.reconnectInterval" type="number" min="1" max="3600" class="input w-40" required />
            <span class="ml-2 text-xs text-gray-500">{{ t('admin.clandes.cfgSeconds') }}</span>
          </div>

          <div class="rounded-lg bg-amber-50 p-3 text-xs text-amber-700 dark:bg-amber-900/20 dark:text-amber-400">
            {{ t('admin.clandes.cfgRestartWarning') }}
          </div>

          <div class="flex items-center gap-3">
            <button type="submit" class="btn btn-primary" :disabled="saving">
              {{ saving ? t('admin.clandes.cfgRestarting') : t('admin.clandes.cfgSave') }}
            </button>
            <button type="button" class="btn btn-secondary" :disabled="saving" @click="resetForm">
              {{ t('common.reset') }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import { adminAPI } from '@/api'
import { useAppStore } from '@/stores'
import type { ClandesConfig, ClandesStatus } from '@/api/admin/clandes'

const { t } = useI18n()
const appStore = useAppStore()

const status = ref<ClandesStatus | null>(null)
const config = ref<ClandesConfig | null>(null)
const loading = ref(false)
const syncing = ref(false)
const saving = ref(false)
const showToken = ref(false)
const tokenTouched = ref(false)

const form = reactive({
  enabled: false,
  addr: '',
  authToken: '',
  reconnectInterval: 5
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

async function fetchConfig() {
  try {
    const cfg = await adminAPI.clandes.getConfig()
    config.value = cfg
    resetForm()
  } catch (e) {
    appStore.showError((e as { message?: string })?.message ?? t('admin.clandes.loadError'))
  }
}

function resetForm() {
  if (!config.value) return
  form.enabled = config.value.enabled
  form.addr = config.value.addr
  form.authToken = ''
  form.reconnectInterval = config.value.reconnect_interval || 5
  tokenTouched.value = false
  showToken.value = false
}

function clearToken() {
  form.authToken = ''
  tokenTouched.value = true
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

async function saveConfig() {
  if (!confirm(t('admin.clandes.cfgRestartConfirm'))) return
  saving.value = true
  try {
    // auth_token: null = keep; "" = clear; else new value
    const authToken = tokenTouched.value ? form.authToken : null
    await adminAPI.clandes.updateConfig({
      enabled: form.enabled,
      addr: form.addr.trim(),
      auth_token: authToken,
      reconnect_interval: form.reconnectInterval
    })
    appStore.showSuccess(t('admin.clandes.cfgSavedRestarting'))
    pollUntilAlive()
  } catch (e) {
    appStore.showError((e as { message?: string })?.message ?? t('admin.clandes.cfgSaveFailed'))
    saving.value = false
  }
}

function pollUntilAlive() {
  const started = Date.now()
  const tick = async () => {
    try {
      await fetchStatus()
      await fetchConfig()
      saving.value = false
    } catch {
      if (Date.now() - started < 60_000) {
        setTimeout(tick, 2000)
      } else {
        saving.value = false
      }
    }
  }
  setTimeout(tick, 3000)
}

onMounted(() => {
  fetchStatus()
  fetchConfig()
  refreshTimer = setInterval(fetchStatus, 30_000)
})

onBeforeUnmount(() => {
  if (refreshTimer !== null) clearInterval(refreshTimer)
})
</script>
