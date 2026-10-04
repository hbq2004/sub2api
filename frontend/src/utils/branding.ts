import { sanitizeUrl } from '@/utils/url'
import type { PublicSettings } from '@/types'

const DEFAULT_SITE_NAME = '\u667a\u9a7f AI'

export function applySiteBranding(settings: PublicSettings): PublicSettings {
  const siteName = settings.site_name?.trim()
  const subtitle = settings.site_subtitle?.trim()
  return {
    ...settings,
    site_name: !siteName || /^sub2api$/i.test(siteName) ? DEFAULT_SITE_NAME : siteName,
    site_subtitle: subtitle === 'Subscription to API Conversion Platform'
      ? 'GPT API \u670d\u52a1\u5e73\u53f0'
      : settings.site_subtitle,
  }
}

export function replaceSiteBranding(text: string, siteName = DEFAULT_SITE_NAME): string {
  return text.replace(/\bSub2API\b/g, () => siteName)
}

export function updateFavicon(logoUrl: string): void {
  const sanitizedLogoUrl = sanitizeUrl(logoUrl, {
    allowRelative: true,
    allowDataUrl: true,
  })
  if (!sanitizedLogoUrl) {
    return
  }

  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
  if (!link) {
    link = document.createElement('link')
    link.rel = 'icon'
    document.head.appendChild(link)
  }

  link.type = sanitizedLogoUrl.endsWith('.svg') ? 'image/svg+xml' : 'image/x-icon'
  link.href = sanitizedLogoUrl
}
