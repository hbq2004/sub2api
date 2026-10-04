<template>
  <BaseDialog :show="show" :title="t('admin.accounts.localCloudSync.title')" width="wide" @close="close">
    <div class="space-y-4">
      <div class="flex flex-wrap items-center justify-between gap-2 text-sm text-gray-600 dark:text-dark-300">
        <span>{{ t('admin.accounts.localCloudSync.selected', { count: accountIds.length }) }}</span>
        <span class="font-mono text-xs">api.zynexus.top</span>
      </div>

      <form id="local-cloud-sync-form" class="grid gap-3 sm:grid-cols-2" @submit.prevent="previewSync">
        <label class="block sm:col-span-2">
          <span class="input-label">{{ t('admin.accounts.localCloudSync.email') }}</span>
          <input v-model.trim="form.cloudEmail" class="input" type="email" autocomplete="username" required />
        </label>
        <label class="block sm:col-span-2">
          <span class="input-label">{{ t('admin.accounts.localCloudSync.password') }}</span>
          <input v-model="form.cloudPassword" class="input" type="password" autocomplete="current-password" required />
        </label>
        <label class="block">
          <span class="input-label">{{ t('admin.accounts.localCloudSync.cloudCode') }}</span>
          <input v-model.trim="form.cloudCode" class="input font-mono" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required />
        </label>
        <label class="block">
          <span class="input-label">{{ t('admin.accounts.localCloudSync.localCode') }}</span>
          <input v-model.trim="form.localCode" class="input font-mono" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="off" />
        </label>
      </form>

      <p v-if="error" role="alert" class="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">{{ error }}</p>
      <p v-if="completed" role="status" class="rounded border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-300">
        {{ t('admin.accounts.localCloudSync.completed') }}
        <span v-if="privacySummary">{{ t('admin.accounts.localCloudSync.privacySummary', {
          off: privacySummary.training_off ?? 0,
          failed: privacySummary.training_set_failed ?? 0,
          other: Object.entries(privacySummary).filter(([key]) => !['training_off', 'training_set_failed'].includes(key)).reduce((sum, [, count]) => sum + count, 0)
        }) }}</span>
      </p>

      <div v-if="preview" class="space-y-2">
        <div v-if="reviewRows.length" class="space-y-1 border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-900/20 dark:text-amber-200">
          <p class="font-medium">{{ t('admin.accounts.localCloudSync.updateWarning', { count: reviewRows.length }) }}</p>
          <div v-for="row in reviewRows" :key="row.localId" class="border-t border-amber-200 pt-1 first:border-t-0 dark:border-amber-800">
            <span class="font-medium">{{ row.label }}</span>
            <span> · {{ row.differences?.join(', ') }}</span>
            <div v-if="row.groupDifference" class="pl-3">
              {{ t('admin.accounts.localCloudSync.localGroups') }}: {{ row.groupDifference.local.join('、') || '—' }}
              / {{ t('admin.accounts.localCloudSync.cloudGroups') }}: {{ row.groupDifference.cloud.join('、') || '—' }}
            </div>
            <div v-if="row.settingDifferences?.length" class="max-h-28 overflow-auto pl-3">
              <div v-for="setting in row.settingDifferences" :key="setting.field" class="break-all">
                {{ setting.field }} · {{ t('admin.accounts.localCloudSync.localValue') }}: {{ displaySetting(setting.local) }}
                / {{ t('admin.accounts.localCloudSync.cloudValue') }}: {{ displaySetting(setting.cloud) }}
              </div>
            </div>
          </div>
        </div>
        <p v-if="hasConflict" role="alert" class="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm font-medium text-red-700 dark:border-red-700 dark:bg-red-900/20 dark:text-red-300">
          {{ t('admin.accounts.localCloudSync.conflictWarning', { count: countAction('conflict') }) }}
        </p>
        <div v-if="hasConflict" class="space-y-1 rounded border border-red-200 bg-red-50/50 p-3 text-xs dark:border-red-800 dark:bg-red-900/10">
          <div v-for="row in conflictRows" :key="`${row.kind}-${row.localId}`" class="text-red-800 dark:text-red-300">
            <span class="font-medium">{{ row.label }}</span>
            <span> · {{ row.differences?.join(', ') || t('admin.accounts.localCloudSync.conflict') }}</span>
            <span v-if="row.groupDifference" class="block pl-3">
              {{ t('admin.accounts.localCloudSync.localGroups') }}: {{ row.groupDifference.local.join('、') || '—' }}
              / {{ t('admin.accounts.localCloudSync.cloudGroups') }}: {{ row.groupDifference.cloud.join('、') || '—' }}
            </span>
            <div v-if="row.settingDifferences?.length" class="max-h-28 overflow-auto pl-3">
              <div v-for="setting in row.settingDifferences" :key="setting.field" class="break-all">
                {{ setting.field }} · {{ t('admin.accounts.localCloudSync.localValue') }}: {{ displaySetting(setting.local) }}
                / {{ t('admin.accounts.localCloudSync.cloudValue') }}: {{ displaySetting(setting.cloud) }}
              </div>
            </div>
          </div>
        </div>
        <div class="flex flex-wrap gap-2 text-xs">
          <span v-for="action in actions" :key="action" class="rounded border border-gray-200 px-2 py-1 dark:border-dark-600">
            {{ t(`admin.accounts.localCloudSync.${action}`) }}: {{ countAction(action) }}
          </span>
        </div>
        <div class="max-h-64 overflow-auto border-y border-gray-200 dark:border-dark-700">
          <div v-for="(row, index) in preview.plan" :key="`${row.kind}-${row.localId}-${index}`"
            class="border-b border-gray-100 px-1 py-2 text-sm last:border-b-0 dark:border-dark-700">
            <div class="flex items-center gap-3">
              <span class="w-16 shrink-0 text-xs text-gray-500">{{ t(`admin.accounts.localCloudSync.${row.kind}`) }}</span>
              <span class="min-w-0 flex-1 break-words">{{ row.label }}</span>
              <span :class="row.action === 'conflict' ? 'text-red-600 dark:text-red-400' : 'text-gray-500 dark:text-dark-400'">
                {{ t(`admin.accounts.localCloudSync.${row.action}`) }}
              </span>
            </div>
            <div v-if="row.differences?.length || row.ignored?.length" class="mt-1 pl-[4.75rem] text-xs text-gray-500 dark:text-dark-400">
              <div v-if="row.differences?.length">{{ t('admin.accounts.localCloudSync.differentFields') }}: {{ row.differences.join(', ') }}</div>
              <div v-if="row.ignored?.length">{{ t('admin.accounts.localCloudSync.ignoredRuntime') }}: {{ row.ignored.map(reason => t(`admin.accounts.localCloudSync.${reason}`)).join(', ') }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <template #footer>
      <div class="flex w-full justify-between gap-2">
        <button type="button" class="btn btn-secondary" :disabled="!!busy" @click="close">{{ t('common.close') }}</button>
        <div class="flex gap-2">
          <button type="submit" form="local-cloud-sync-form" class="btn btn-secondary" :disabled="!!busy || !accountIds.length">
            <Icon name="refresh" size="sm" class="mr-1.5" />
            {{ busy === 'preview' ? t('admin.accounts.localCloudSync.previewing') : t('admin.accounts.localCloudSync.preview') }}
          </button>
          <button type="button" class="btn btn-primary" :disabled="!!busy || !canApply" @click="applySync">
            <Icon name="cloud" size="sm" class="mr-1.5" />
            {{ busy === 'apply' ? t('admin.accounts.localCloudSync.syncing') : t('admin.accounts.localCloudSync.apply') }}
          </button>
        </div>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import Icon from '@/components/icons/Icon.vue'

type Action = 'create' | 'update' | 'skip' | 'conflict'
interface PlanRow { kind: 'groups' | 'accounts'; action: Action; label: string; localId: number;
  differences?: string[]; ignored?: Array<'oauth_tokens' | 'runtime_usage'>;
  settingDifferences?: Array<{ field: string; local: string | number | boolean | null;
    cloud: string | number | boolean | null }>;
  groupDifference?: { local: string[]; cloud: string[] } }
interface Preview { plan: PlanRow[]; digest: string; previewTicket: string | null }

const props = defineProps<{ show: boolean; accountIds: number[] }>()
const emit = defineEmits<{ (e: 'close'): void; (e: 'synced'): void }>()
const { t } = useI18n()
const actions: Action[] = ['create', 'update', 'skip', 'conflict']
const form = reactive({ cloudEmail: '', cloudPassword: '', cloudCode: '', localCode: '' })
const preview = ref<Preview | null>(null)
const busy = ref<'preview' | 'apply' | null>(null)
const error = ref('')
const completed = ref(false)
const privacySummary = ref<Record<string, number> | null>(null)
const hasConflict = computed(() => preview.value?.plan.some(row => row.action === 'conflict') ?? false)
const conflictRows = computed(() => preview.value?.plan.filter(row => row.action === 'conflict') ?? [])
const reviewRows = computed(() => preview.value?.plan.filter(row => row.kind === 'accounts' &&
  row.action === 'update' && row.differences?.length) ?? [])
const canApply = computed(() => !!preview.value?.previewTicket && !completed.value && !hasConflict.value &&
  preview.value.plan.some(row => row.action === 'create' || row.action === 'update'))
const countAction = (action: Action) => preview.value?.plan.filter(row => row.action === action).length ?? 0
const displaySetting = (value: string | number | boolean | null) =>
  value === null ? t('admin.accounts.localCloudSync.unsetValue') : String(value)

watch(() => [form.cloudEmail, form.localCode,
  props.accountIds.join(',')], () => {
  if (busy.value !== 'apply') { preview.value = null; completed.value = false }
})
watch(() => props.show, show => {
  if (!show) {
    form.cloudPassword = ''
    form.cloudCode = ''
    form.localCode = ''
    preview.value = null
    error.value = ''
    completed.value = false
    privacySummary.value = null
  }
})

function close() {
  if (!busy.value) emit('close')
}

async function request(path: 'preview' | 'apply', expectedPlan?: string, previewTicket?: string) {
  const token = localStorage.getItem('auth_token')
  if (!token) throw new Error(t('admin.accounts.localCloudSync.localLogin'))
  let response: Response
  try {
    response = await fetch(`http://127.0.0.1:8769/${path}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(path === 'preview'
        ? { ...form, accountIds: props.accountIds }
        : { accountIds: props.accountIds, localCode: form.localCode,
          expectedPlan, previewTicket })
    })
  } catch {
    throw new Error(t('admin.accounts.localCloudSync.agentUnavailable'))
  }
  const result = await response.json()
  if (!response.ok) throw new Error(result.error || t('admin.accounts.localCloudSync.failed'))
  return result
}

async function previewSync() {
  if (busy.value) return
  busy.value = 'preview'
  error.value = ''
  completed.value = false
  privacySummary.value = null
  try {
    preview.value = await request('preview') as Preview
    form.cloudPassword = ''
    form.cloudCode = ''
  } catch (cause) {
    preview.value = null
    error.value = cause instanceof Error ? cause.message : t('admin.accounts.localCloudSync.failed')
  } finally {
    busy.value = null
  }
}

async function applySync() {
  if (busy.value || !canApply.value || !preview.value) return
  busy.value = 'apply'
  error.value = ''
  try {
    const result = await request('apply', preview.value.digest, preview.value.previewTicket ?? undefined)
    privacySummary.value = result.privacy ?? null
    completed.value = true
    form.cloudPassword = ''
    form.cloudCode = ''
    form.localCode = ''
    emit('synced')
  } catch (cause) {
    preview.value = null
    error.value = cause instanceof Error ? cause.message : t('admin.accounts.localCloudSync.failed')
  } finally {
    busy.value = null
  }
}
</script>
