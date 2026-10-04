import { beforeEach, describe, expect, it } from 'vitest'
import { applySiteBranding, replaceSiteBranding, updateFavicon } from '@/utils/branding'
import type { PublicSettings } from '@/types'

describe('site branding', () => {
  it('rebrands legacy public settings without mutating them or changing access controls', () => {
    const original = {
      site_name: 'Sub2API',
      site_subtitle: 'Subscription to API Conversion Platform',
      registration_enabled: false,
      github_oauth_enabled: false,
    } as PublicSettings
    const branded = applySiteBranding(original)

    expect(branded.site_name).toBe('智驿 AI')
    expect(branded.site_subtitle).toBe('GPT API 服务平台')
    expect(branded.registration_enabled).toBe(false)
    expect(branded.github_oauth_enabled).toBe(false)
    expect(original.site_name).toBe('Sub2API')
  })

  it('preserves custom branding and API configuration identifiers', () => {
    const custom = { site_name: 'Custom site', site_subtitle: '' } as PublicSettings
    expect(applySiteBranding(custom)).toEqual(custom)
    expect(replaceSiteBranding('Sub2API uses SUB2API_API_KEY and model_providers.sub2api'))
      .toBe('智驿 AI uses SUB2API_API_KEY and model_providers.sub2api')
  })
})

describe('updateFavicon', () => {
  beforeEach(() => {
    document.head.innerHTML = '<link rel="icon" href="/logo.svg">'
  })

  it('replaces the default favicon with the configured logo', () => {
    updateFavicon('https://example.com/custom-logo.png')

    const link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
    expect(link?.href).toBe('https://example.com/custom-logo.png')
  })

  it('ignores unsafe logo URLs', () => {
    updateFavicon('javascript:alert(1)')

    const link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
    expect(link?.getAttribute('href')).toBe('/logo.svg')
  })
})
