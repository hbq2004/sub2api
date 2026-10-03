import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ResetPasswordView from '@/views/auth/ResetPasswordView.vue'

const { resetPasswordMock, showErrorMock } = vi.hoisted(() => ({
  resetPasswordMock: vi.fn(),
  showErrorMock: vi.fn()
}))

vi.mock('vue-router', () => ({ useRoute: () => ({ query: { email: 'user@example.com', token: 'test-token' } }) }))
vi.mock('vue-i18n', async () => ({
  ...await vi.importActual<typeof import('vue-i18n')>('vue-i18n'),
  useI18n: () => ({ t: (key: string) => key })
}))
vi.mock('@/stores', () => ({ useAppStore: () => ({ showError: showErrorMock, showSuccess: vi.fn() }) }))
vi.mock('@/api/auth', () => ({ resetPassword: resetPasswordMock }))

describe('ResetPasswordView', () => {
  beforeEach(() => {
    resetPasswordMock.mockReset()
    showErrorMock.mockReset()
  })

  it('displays an expired token returned by the real API error envelope', async () => {
    resetPasswordMock.mockRejectedValueOnce({ reason: 'INVALID_RESET_TOKEN', message: 'raw server error' })
    const wrapper = mount(ResetPasswordView, {
      global: { stubs: { AuthLayout: { template: '<div><slot /></div>' }, Icon: true, RouterLink: true } }
    })
    await flushPromises()
    await wrapper.get('#password').setValue('secret-123')
    await wrapper.get('#confirmPassword').setValue('secret-123')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toBe('auth.invalidOrExpiredToken')
    expect(showErrorMock).toHaveBeenCalledWith('auth.invalidOrExpiredToken')
  })
})
