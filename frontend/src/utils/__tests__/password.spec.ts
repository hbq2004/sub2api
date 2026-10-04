import { describe, expect, it } from 'vitest'
import { isPasswordTooLong } from '@/utils/password'

describe('password byte limit', () => {
  it('matches bcrypt boundaries for ASCII, Chinese characters, and emoji', () => {
    expect(isPasswordTooLong('a'.repeat(72))).toBe(false)
    expect(isPasswordTooLong('a'.repeat(73))).toBe(true)
    expect(isPasswordTooLong('\u4e2d'.repeat(24))).toBe(false)
    expect(isPasswordTooLong('\u4e2d'.repeat(25))).toBe(true)
    expect(isPasswordTooLong('\u{1f600}'.repeat(18))).toBe(false)
    expect(isPasswordTooLong('\u{1f600}'.repeat(19))).toBe(true)
  })
})
