import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdirSync, writeFileSync } from 'node:fs'

const require = createRequire(import.meta.url)
const { chromium } = require('C:/Users/hbq/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright')
const origin = process.env.OAUTH_QA_ORIGIN || 'http://127.0.0.1:4175'
const directory = 'D:/Desktop/sub2api/output/oauth-bugfix'
mkdirSync(directory, { recursive: true })
const browser = await chromium.launch({ headless: true })
const checks = []
const runtimeErrors = []

async function checkLayout(page, label) {
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `${label}: horizontal overflow`)
  const overflowingInputs = await page.locator('input').evaluateAll(inputs => inputs.filter(input => {
    const bounds = input.getBoundingClientRect()
    return bounds.width > 2 && (bounds.left < 0 || bounds.right > innerWidth)
  }).length)
  assert.equal(overflowingInputs, 0, `${label}: inputs outside viewport`)
  await page.screenshot({ path: `${directory}/${label}.png`, fullPage: true })
  checks.push(label)
}

try {
  for (const width of [1440, 390, 320]) {
    const context = await browser.newContext({ locale: 'zh-CN', viewport: { width, height: width > 500 ? 960 : 844 } })
    const page = await context.newPage()
    page.on('pageerror', error => runtimeErrors.push(error.message))
    let completion = { error: 'registration_completion_required', provider: 'github', resolved_email: 'qa@example.invalid', redirect: '/keys' }
    let completionRequests = 0
    let totpRequests = 0
    await page.route('**/api/v1/auth/oauth/pending/exchange', route => {
      completionRequests++
      return route.fulfill({ status: 200, json: { code: 0, data: completion } })
    })
    await page.route('**/api/v1/auth/login/2fa', route => {
      totpRequests++
      return route.fulfill({ status: 400, json: { code: 400, message: 'Invalid verification code', reason: 'INVALID_TOTP_CODE' } })
    })
    await page.goto(`${origin}/auth/oauth/callback#error=provider_error&error_description=Access+denied`, { waitUntil: 'networkidle' })
    assert.equal(completionRequests, 0)
    assert.ok((await page.locator('body').innerText()).includes('Access denied'))
    assert.equal(await page.locator('input[readonly]').count(), 0)
    assert.equal(new URL(page.url()).hash, '')
    await checkLayout(page, `cancel-${width}`)
    await page.getByRole('button', { name: /返回登录|Back to Login/ }).click()
    await page.waitForURL('**/login')

    completion = { error: 'registration_completion_required', provider: 'github', resolved_email: 'qa@example.invalid', redirect: '/keys' }
    await page.goto(`${origin}/auth/oauth/callback`, { waitUntil: 'networkidle' })
    assert.equal(await page.locator('input[type="password"]').count(), 2)
    assert.equal(await page.locator('input[type="email"]').inputValue(), 'qa@example.invalid')
    await checkLayout(page, `registration-${width}`)

    completion = { error: 'session_expired' }
    await page.reload({ waitUntil: 'networkidle' })
    assert.equal(await page.locator('input[readonly]').count(), 0)
    assert.ok((await page.locator('body').innerText()).includes('session_expired'))
    await checkLayout(page, `expired-${width}`)

    completion = { requires_2fa: true, temp_token: 'qa-temporary-challenge', user_email_masked: 'q***a@example.invalid', provider: 'github', redirect: '/keys' }
    await page.reload({ waitUntil: 'networkidle' })
    const digits = page.locator('input[maxlength="1"]')
    assert.equal(await digits.count(), 6)
    assert.equal(await digits.evaluateAll(inputs => inputs.some(input => {
      const bounds = input.getBoundingClientRect()
      const parentBounds = input.parentElement.getBoundingClientRect()
      return bounds.left < parentBounds.left - 1 || bounds.right > parentBounds.right + 1
    })), false)
    await checkLayout(page, `totp-${width}`)
    const previousRequests = totpRequests
    for (let index = 0; index < 6; index++) await digits.nth(index).fill('1')
    await page.waitForFunction(() => Array.from(document.querySelectorAll('input[maxlength="1"]')).every(input => !input.disabled))
    assert.equal(totpRequests, previousRequests + 1)
    assert.ok((await page.locator('body').innerText()).includes('Invalid verification code'))
    await page.getByRole('button', { name: /取消|Cancel/, exact: true }).click()
    await page.waitForURL('**/login')
    checks.push(`totp-retry-cancel-${width}`)
    await context.close()
  }
  assert.deepEqual(runtimeErrors, [])
  writeFileSync(`${directory}/browser-report.json`, JSON.stringify({ passed: true, checks, runtimeErrors }, null, 2))
  console.log(JSON.stringify({ passed: true, checks }))
} catch (error) {
  writeFileSync(`${directory}/browser-report.json`, JSON.stringify({ passed: false, checks, error: error.message, runtimeErrors }, null, 2))
  console.error(error.message)
  process.exitCode = 1
} finally {
  await browser.close()
}
