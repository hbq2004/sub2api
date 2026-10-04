import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import OAuthCallbackView from '@/views/auth/OAuthCallbackView.vue'

const {
  routeState,
  locationState,
  routerReplaceMock,
  showErrorMock,
  showSuccessMock,
  setTokenMock,
  login2FAMock,
  copyToClipboardMock,
  exchangePendingOAuthCompletionMock,
  apiPostMock,
} = vi.hoisted(() => ({
  routeState: {
    path: '/auth/callback',
    query: {} as Record<string, unknown>,
  },
  locationState: {
    current: {
      href: 'http://localhost/auth/callback',
      hash: '',
    } as { href: string; hash: string },
  },
  routerReplaceMock: vi.fn(),
  showErrorMock: vi.fn(),
  showSuccessMock: vi.fn(),
  setTokenMock: vi.fn(),
  login2FAMock: vi.fn(),
  copyToClipboardMock: vi.fn(),
  exchangePendingOAuthCompletionMock: vi.fn(),
  apiPostMock: vi.fn(),
}))

vi.mock('vue-router', () => ({
  useRoute: () => routeState,
  useRouter: () => ({
    replace: (...args: any[]) => routerReplaceMock(...args),
  }),
}))

vi.mock('vue-i18n', () => ({
  useI18n: () => ({
    t: (key: string) => key,
  }),
}))

vi.mock('@/stores', () => ({
  useAuthStore: () => ({
    setToken: (...args: any[]) => setTokenMock(...args),
    login2FA: (...args: any[]) => login2FAMock(...args),
  }),
  useAppStore: () => ({
    showError: (...args: any[]) => showErrorMock(...args),
    showSuccess: (...args: any[]) => showSuccessMock(...args),
  }),
}))

vi.mock('@/api/client', () => ({
  apiClient: {
    post: (...args: any[]) => apiPostMock(...args),
  },
}))

vi.mock('@/api/auth', async () => {
  const actual = await vi.importActual<typeof import('@/api/auth')>('@/api/auth')
  return {
    ...actual,
    exchangePendingOAuthCompletion: (...args: any[]) => exchangePendingOAuthCompletionMock(...args),
    persistOAuthTokenContext: vi.fn(),
  }
})

vi.mock('@/composables/useClipboard', () => ({
  useClipboard: () => ({
    copyToClipboard: (...args: any[]) => copyToClipboardMock(...args),
  }),
}))

describe('OAuthCallbackView', () => {
  beforeEach(() => {
    routeState.path = '/auth/callback'
    routeState.query = {}
    locationState.current = {
      href: 'http://localhost/auth/callback',
      hash: '',
    }
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: locationState.current,
    })
    routerReplaceMock.mockReset()
    showErrorMock.mockReset()
    showSuccessMock.mockReset()
    setTokenMock.mockReset()
    login2FAMock.mockReset()
    copyToClipboardMock.mockReset()
    exchangePendingOAuthCompletionMock.mockReset()
    apiPostMock.mockReset()
    window.sessionStorage.clear()
  })

  it.each(['fragment', 'query'])('shows a retry action after an OAuth %s error without exchanging a pending session', async (source) => {
    routeState.path = '/auth/oauth/callback'
    if (source === 'fragment') {
      locationState.current.hash = '#error=provider_error&error_description=Access+denied'
    } else {
      routeState.query = { error: 'access_denied', error_description: 'Access denied' }
    }
    window.sessionStorage.setItem('email_oauth_pending_provider', 'github')
    const wrapper = mount(OAuthCallbackView)
    await flushPromises()

    expect(wrapper.text()).toContain('Access denied')
    expect(wrapper.find('input[readonly]').exists()).toBe(false)
    expect(exchangePendingOAuthCompletionMock).not.toHaveBeenCalled()
    expect(window.sessionStorage.getItem('email_oauth_pending_provider')).toBeNull()
    await wrapper.get('button').trigger('click')
    expect(routerReplaceMock).toHaveBeenCalledWith('/login')
  })

  it('shows an error view when a pending completion reports an unsupported result', async () => {
    routeState.path = '/auth/oauth/callback'
    exchangePendingOAuthCompletionMock.mockResolvedValue({ error: 'registration_disabled' })
    const wrapper = mount(OAuthCallbackView)
    await flushPromises()

    expect(wrapper.find('input[readonly]').exists()).toBe(false)
    expect(wrapper.text()).toContain('registration_disabled')
    expect(wrapper.text()).toContain('auth.backToLogin')
  })

  it('keeps token-load failures out of the manual authorization-code view', async () => {
    routeState.path = '/auth/oauth/callback'
    locationState.current.hash = '#access_token=test-token&redirect=%2Fkeys'
    setTokenMock.mockRejectedValue(new Error('Session expired'))
    const wrapper = mount(OAuthCallbackView)
    await flushPromises()

    expect(wrapper.text()).toContain('Session expired')
    expect(wrapper.find('input[readonly]').exists()).toBe(false)
    expect(routerReplaceMock).not.toHaveBeenCalled()
  })

  it('decodes tokens and the requested route once and removes the callback fragment', async () => {
    routeState.path = '/auth/oauth/callback'
    const destination = '/keys?filter=a%2Fb&label=two words#details'
    locationState.current.hash = '#' + new URLSearchParams({
      access_token: 'test-token+/%=value', redirect: destination
    }).toString()
    const previousHistoryState = window.history.state
    const historySpy = vi.spyOn(window.history, 'replaceState')
    try {
      mount(OAuthCallbackView)
      await flushPromises()

      expect(setTokenMock).toHaveBeenCalledWith('test-token+/%=value')
      expect(routerReplaceMock).toHaveBeenCalledWith(destination)
      expect(historySpy).toHaveBeenCalledWith(previousHistoryState, '', '/auth/callback')
    } finally {
      historySpy.mockRestore()
    }
  })

  it('waits for TOTP before completing GitHub sign-in and preserves the requested route', async () => {
    routeState.path = '/auth/oauth/callback'
    exchangePendingOAuthCompletionMock.mockResolvedValue({
      requires_2fa: true, temp_token: 'test-challenge', user_email_masked: 'o***r@example.com', redirect: '/keys'
    })
    login2FAMock.mockResolvedValue({})
    const wrapper = mount(OAuthCallbackView, { global: { stubs: { TotpLoginModal: true } } })
    await flushPromises()

    const modal = wrapper.findComponent({ name: 'TotpLoginModal' })
    expect(modal.exists()).toBe(true)
    expect(modal.props('tempToken')).toBe('test-challenge')
    expect(setTokenMock).not.toHaveBeenCalled()
    expect(routerReplaceMock).not.toHaveBeenCalled()
    modal.vm.$emit('verify', '123456')
    await flushPromises()
    expect(login2FAMock).toHaveBeenCalledWith('test-challenge', '123456')
    expect(routerReplaceMock).toHaveBeenCalledWith('/keys')
  })

  it('renders localized callback copy actions', () => {
    routeState.query = {
      code: 'oauth-code',
      state: 'oauth-state',
    }

    const wrapper = mount(OAuthCallbackView)

    expect(wrapper.text()).toContain('auth.oauth.callbackTitle')
    expect(wrapper.text()).toContain('auth.oauth.callbackHint')
    expect(wrapper.text()).toContain('common.copy')
    expect(wrapper.find('input[value="oauth-code"]').exists()).toBe(true)
    expect(wrapper.find('input[value="oauth-state"]').exists()).toBe(true)
  })

  it('sends callback errors to toast instead of rendering inline red text', () => {
    routeState.query = {
      error: 'oauth failed',
    }

    const wrapper = mount(OAuthCallbackView)

    expect(showErrorMock).toHaveBeenCalledWith('oauth failed')
    expect(wrapper.text()).not.toContain('oauth failed')
    expect(wrapper.find('.bg-red-50').exists()).toBe(false)
  })

  it('does not render manual copy fields for direct email oauth callback visits', async () => {
    routeState.path = '/auth/oauth/callback'
    exchangePendingOAuthCompletionMock.mockRejectedValue(new Error('pending session not found'))

    const wrapper = mount(OAuthCallbackView)
    await vi.dynamicImportSettled()

    expect(exchangePendingOAuthCompletionMock).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('auth.emailOAuth.callbackFailed')
    expect(wrapper.text()).toContain('pending session not found')
    expect(wrapper.text()).toContain('auth.backToLogin')
    expect(wrapper.find('input[readonly]').exists()).toBe(false)
  })

  it('forwards frontend email oauth provider callbacks back to the backend callback endpoint', async () => {
    routeState.path = '/auth/oauth/callback'
    routeState.query = {
      code: 'provider-code',
      state: 'provider-state',
    }
    window.sessionStorage.setItem('email_oauth_pending_provider', 'google')

    mount(OAuthCallbackView)
    await vi.dynamicImportSettled()

    expect(locationState.current.href).toBe(
      '/api/v1/auth/oauth/google/callback?code=provider-code&state=provider-state'
    )
    expect(exchangePendingOAuthCompletionMock).not.toHaveBeenCalled()
  })

  it('submits stored affiliate code when completing invited email oauth registration', async () => {
    routeState.path = '/auth/oauth/callback'
    exchangePendingOAuthCompletionMock.mockResolvedValue({
      error: 'invitation_required',
      provider: 'google',
      redirect: '/dashboard',
      resolved_email: 'pending@example.com',
      invitation_required: true,
    })
    apiPostMock.mockResolvedValue({
      data: {
        access_token: 'token-1',
      },
    })
    window.sessionStorage.setItem('oauth_aff_code', 'AFF456')

    const wrapper = mount(OAuthCallbackView)
    await vi.dynamicImportSettled()
    const passwordInputs = wrapper.findAll('input[type="password"]')
    await passwordInputs[0].setValue('secret-123')
    await passwordInputs[1].setValue('secret-123')
    const invitationInput = wrapper.find('input[type="text"]')
    await invitationInput.setValue('INVITE456')
    await wrapper.findAll('button').at(0)?.trigger('click')

    expect(apiPostMock).toHaveBeenCalledWith('/auth/oauth/google/complete-registration', {
      password: 'secret-123',
      invitation_code: 'INVITE456',
      aff_code: 'AFF456',
    })
    expect(setTokenMock).toHaveBeenCalledWith('token-1')
  })

  it('completes email oauth registration with readonly email and without posting email', async () => {
    routeState.path = '/auth/oauth/callback'
    exchangePendingOAuthCompletionMock.mockResolvedValue({
      error: 'registration_completion_required',
      provider: 'github',
      redirect: '/dashboard',
      resolved_email: 'verified@example.com',
      invitation_required: false,
    })
    apiPostMock.mockResolvedValue({
      data: {
        access_token: 'token-2',
      },
    })

    const wrapper = mount(OAuthCallbackView)
    await vi.dynamicImportSettled()

    const emailInput = wrapper.find('input[type="email"]')
    expect(emailInput.exists()).toBe(true)
    expect((emailInput.element as HTMLInputElement).value).toBe('verified@example.com')
    expect(emailInput.attributes('readonly')).toBeDefined()
    expect(emailInput.attributes('disabled')).toBeDefined()

    const passwordInputs = wrapper.findAll('input[type="password"]')
    await passwordInputs[0].setValue('secret-456')
    await passwordInputs[1].setValue('secret-456')
    await wrapper.findAll('button').at(0)?.trigger('click')

    expect(apiPostMock).toHaveBeenCalledWith('/auth/oauth/github/complete-registration', {
      password: 'secret-456',
    })
    expect(apiPostMock.mock.calls[0][1]).not.toHaveProperty('email')
    expect(setTokenMock).toHaveBeenCalledWith('token-2')
  })
})
