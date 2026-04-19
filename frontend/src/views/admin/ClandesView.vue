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

        <div v-if="!status.enabled" class="mt-5 rounded-lg bg-amber-50 p-4 text-sm text-amber-700 dark:bg-amber-900/20 dark:text-amber-400">
          {{ t('admin.clandes.notEnabled') }}
        </div>

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
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import { adminAPI } from '@/api'
import { useAppStore } from '@/stores'
import type { ClandesStatus } from '@/api/admin/clandes'

const { t } = useI18n()
const appStore = useAppStore()

const status = ref<ClandesStatus | null>(null)
const loading = ref(false)
const syncing = ref(false)

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

onMounted(() => {
  fetchStatus()
  refreshTimer = setInterval(fetchStatus, 30_000)
})

onBeforeUnmount(() => {
  if (refreshTimer !== null) clearInterval(refreshTimer)
})
</script>
