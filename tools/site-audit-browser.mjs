import { createRequire } from 'node:module'
import { execFileSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import assert from 'node:assert/strict'

const require = createRequire(import.meta.url)
const { chromium } = require('C:/Users/hbq/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright')
const origin = 'http://127.0.0.1:4186'
const directory = 'D:/Desktop/sub2api/output/site-audit-20261002'
const docker = 'C:/Users/hbq/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe'
mkdirSync(directory, { recursive: true })
const envRaw = execFileSync(docker, ['inspect', 'sub2api-email-qa-20261002-app', '--format', '{{json .Config.Env}}'], { encoding: 'utf8', windowsHide: true })
const environment = Object.fromEntries(JSON.parse(envRaw).map(item => [item.slice(0, item.indexOf('=')), item.slice(item.indexOf('=') + 1)]))
const browser = await chromium.launch({ headless: true })
const checks = []
const failures = []
const runtimeErrors = []
const record = name => { checks.push(name); console.log(`PASS ${name}`) }
async function api(context, method, path, data, token) {
  const response = await context.request.fetch(`${origin}/api/v1${path}`, {
    method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, ...(data === undefined ? {} : { data })
  })
  return { status: response.status(), body: await response.json() }
}
async function checkPage(page, path, label) {
  await page.goto(origin + path, { waitUntil: 'networkidle' })
  const text = await page.locator('body').innerText()
  assert.ok(text.trim().length > 30, `${label} is blank`)
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `${label} overflows`)
  const broken = await page.locator('img').evaluateAll(images => images.filter(image => image.getBoundingClientRect().width > 0 && image.complete && image.naturalWidth === 0).map(image => image.getAttribute('src')))
  assert.deepEqual(broken, [], `${label} has broken images`)
  await page.screenshot({ path: `${directory}/${label}.png`, fullPage: true })
  record(label)
}
async function login(context, email, password) {
  const page = await context.newPage()
  page.on('pageerror', error => runtimeErrors.push(error.message))
  await page.goto(origin + '/login', { waitUntil: 'networkidle' })
  await page.locator('#email').fill(email)
  await page.locator('#password').fill(password)
  await page.locator('button[type="submit"]').click()
  await page.waitForURL('**/dashboard')
  await page.waitForLoadState('networkidle')
  const token = await page.evaluate(() => localStorage.getItem('auth_token'))
  assert.ok(token)
  return { page, token }
}
try {
  const anonymous = await browser.newContext({ locale: 'zh-CN', viewport: { width: 1440, height: 960 } })
  const publicPage = await anonymous.newPage()
  publicPage.on('pageerror', error => runtimeErrors.push(error.message))
  for (const viewport of [{ width: 1440, height: 960 }, { width: 320, height: 568 }]) {
    await publicPage.setViewportSize(viewport)
    for (const path of ['/home', '/login', '/register', '/forgot-password', '/key-usage', '/legal/terms', '/legal/usage-policy']) {
      try { await checkPage(publicPage, path, `public-${path.slice(1).replaceAll('/', '-')}-${viewport.width}`) } catch (error) { failures.push({ path, viewport: viewport.width, error: error.message }) }
    }
  }
  await publicPage.goto(origin + '/keys', { waitUntil: 'networkidle' })
  assert.ok(new URL(publicPage.url()).pathname === '/login')
  record('Anonymous protected page redirects to login')

  const userContext = await browser.newContext({ locale: 'zh-CN', viewport: { width: 1440, height: 960 } })
  const user = await login(userContext, 'qa-user@example.invalid', 'Changed-testing-password-2026')
  for (const viewport of [{ width: 1440, height: 960 }, { width: 320, height: 568 }]) {
    await user.page.setViewportSize(viewport)
    for (const path of ['/dashboard', '/keys', '/usage', '/redeem', '/profile', '/subscriptions', '/orders']) {
      try { await checkPage(user.page, path, `user-${path.slice(1)}-${viewport.width}`) } catch (error) { failures.push({ path, viewport: viewport.width, error: error.message }) }
    }
  }
  assert.equal((await api(userContext, 'GET', '/admin/users', undefined, user.token)).status, 403)
  record('Ordinary user cannot read administrator users')
  await user.page.goto(origin + '/admin/groups', { waitUntil: 'networkidle' })
  assert.ok(!new URL(user.page.url()).pathname.startsWith('/admin'))
  record('Ordinary user cannot navigate into administrator pages')

  const adminContext = await browser.newContext({ locale: 'zh-CN', viewport: { width: 1440, height: 960 } })
  const admin = await login(adminContext, environment.ADMIN_EMAIL, environment.ADMIN_PASSWORD)
  const compliance = await api(adminContext, 'GET', '/admin/compliance', undefined, admin.token)
  if (compliance.body.data?.required) {
    const accepted = await api(adminContext, 'POST', '/admin/compliance/accept', { phrase: compliance.body.data.ack_phrase_en, language: 'en' }, admin.token)
    assert.equal(accepted.status, 200)
  }
  for (const viewport of [{ width: 1440, height: 960 }, { width: 390, height: 844 }]) {
    await admin.page.setViewportSize(viewport)
    for (const path of ['/admin/dashboard', '/admin/users', '/admin/groups', '/admin/accounts', '/admin/usage', '/admin/redeem', '/admin/settings', '/admin/audit-logs']) {
      try { await checkPage(admin.page, path, `admin-${path.split('/').at(-1)}-${viewport.width}`) } catch (error) { failures.push({ path, viewport: viewport.width, error: error.message }) }
    }
  }
  assert.deepEqual(runtimeErrors, [])
  record('No browser runtime errors across public, user, and administrator routes')
} catch (error) {
  failures.push({ error: error.message })
} finally {
  writeFileSync(`${directory}/round2-browser-report.json`, JSON.stringify({ passed: failures.length === 0, checks, failures, runtimeErrors }, null, 2))
  for (const failure of failures) console.log(JSON.stringify(failure))
  await browser.close()
  process.exitCode = failures.length ? 1 : 0
}
