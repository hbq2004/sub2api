<template>
  <div
    class="auth-layout relative flex min-h-screen items-start justify-center overflow-y-auto px-4 py-8 sm:items-center sm:py-10"
  >
    <div class="auth-layout__backdrop pointer-events-none absolute inset-0"></div>

    <main class="relative z-10 min-w-0 w-full max-w-md">
      <router-link
        v-if="!appStore.backendModeEnabled"
        to="/home"
        class="mx-auto mb-5 flex w-fit items-center gap-1.5 rounded-lg px-3 py-2 text-sm text-gray-500 transition-colors hover:bg-white/70 hover:text-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-500/40 dark:text-dark-400 dark:hover:bg-dark-800/70 dark:hover:text-white"
      >
        <Icon name="arrowLeft" size="sm" aria-hidden="true" />
        {{ t('home.backToHome') }}
      </router-link>

      <!-- Logo/Brand -->
      <div class="mb-7 text-center">
        <div
          class="mx-auto mb-4 inline-flex h-16 w-16 items-center justify-center overflow-hidden rounded-lg bg-white shadow-sm ring-1 ring-gray-200/80 dark:bg-dark-800 dark:ring-dark-700"
        >
          <img :src="siteLogo || '/logo-zhiyi-z-20261002.svg'" alt="Logo" class="h-full w-full object-contain" />
        </div>
        <h1 class="text-gradient mb-2 text-3xl font-bold [overflow-wrap:anywhere]">
          {{ siteName }}
        </h1>
        <p class="text-sm text-gray-500 [overflow-wrap:anywhere] dark:text-dark-400">
          {{ siteSubtitle }}
        </p>
      </div>

      <!-- Card Container -->
      <div class="card-glass rounded-2xl p-6 shadow-glass sm:p-8">
        <slot />
      </div>

      <!-- Footer Links -->
      <div class="mt-6 text-center text-sm">
        <slot name="footer" />
      </div>

      <!-- Copyright -->
      <div class="mt-8 text-center text-xs text-gray-400 [overflow-wrap:anywhere] dark:text-dark-500">
        &copy; {{ currentYear }} {{ siteName }}. {{ t('home.footer.allRightsReserved') }}
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAppStore } from '@/stores'
import { sanitizeUrl } from '@/utils/url'
import Icon from '@/components/icons/Icon.vue'

const appStore = useAppStore()
const { t } = useI18n()

const siteName = computed(() => appStore.siteName || '智驿 AI')
const siteLogo = computed(() => sanitizeUrl(appStore.siteLogo || '', { allowRelative: true, allowDataUrl: true }))
const siteSubtitle = computed(() => appStore.cachedPublicSettings?.site_subtitle || t('home.heroSubtitle'))
const currentYear = computed(() => new Date().getFullYear())

onMounted(() => {
  appStore.fetchPublicSettings()
})
</script>

<style scoped>
.auth-layout {
  background: #f8fafc;
}

.dark .auth-layout {
  background: #020617;
}

.auth-layout__backdrop {
  background-image:
    linear-gradient(rgba(20, 184, 166, 0.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(20, 184, 166, 0.045) 1px, transparent 1px),
    linear-gradient(180deg, rgba(20, 184, 166, 0.09), transparent 22%);
  background-size: 56px 56px, 56px 56px, 100% 100%;
}

.dark .auth-layout__backdrop {
  background-image:
    linear-gradient(rgba(45, 212, 191, 0.07) 1px, transparent 1px),
    linear-gradient(90deg, rgba(45, 212, 191, 0.07) 1px, transparent 1px),
    linear-gradient(180deg, rgba(20, 184, 166, 0.1), transparent 22%);
}

.text-gradient {
  @apply bg-gradient-to-r from-primary-600 to-primary-500 bg-clip-text text-transparent;
}
</style>
