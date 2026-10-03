import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const args = process.argv.slice(2)
const value = name => args[args.indexOf(name) + 1]
const origin = value('--origin')
const version = value('--version')
const directory = value('--output')
const credentialFile = args.includes('--credential-file') ? value('--credential-file') : null
assert.ok(/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin), 'Browser verification requires a local origin')
const require = createRequire(import.meta.url)
const { chromium } = require(process.env.SUB2API_PLAYWRIGHT || 'C:/Users/hbq/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright')
mkdirSync(directory, { recursive: true })
const browser = await chromium.launch({ headless: true })
const report = { passed: false, origin, version, checks: [], errors: [], failures: [] }

async function capture(page, path, label) {
  await page.goto(origin + path, { waitUntil: 'networkidle' })
  const body = await page.locator('body').innerText()
  assert.ok(body.trim().length > 30, `${label}: blank page`)
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `${label}: horizontal overflow`)
  const broken = await page.locator('img').evaluateAll(images => images.filter(image =>
    image.getBoundingClientRect().width > 0 && image.complete && image.naturalWidth === 0).map(image => image.getAttribute('src')))
  assert.deepEqual(broken, [], `${label}: broken images`)
  await page.screenshot({ path: join(directory, `${label}.png`), fullPage: true })
  report.checks.push(label)
}
try {
  const settingsResponse = await fetch(`${origin}/api/v1/settings/public`)
  assert.ok(settingsResponse.ok)
  const settings = (await settingsResponse.json()).data
  assert.equal(settings.version, version)
  report.siteName = settings.site_name
  const context = await browser.newContext({ locale: 'zh-CN' })
  const page = await context.newPage()
  page.on('pageerror', error => report.errors.push(error.message))
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({ width, height: width === 1440 ? 960 : 844 })
    for (const path of ['/home', '/login', '/forgot-password']) {
      try { await capture(page, path, `${path.slice(1)}-${width}`) }
      catch (error) { report.failures.push(error.message) }
    }
  }
  await page.goto(origin + '/keys', { waitUntil: 'networkidle' })
  assert.equal(new URL(page.url()).pathname, '/login')
  report.checks.push('Anonymous personal-key page redirects to login')
  await context.close()
  if (credentialFile) {
    const { token } = JSON.parse(readFileSync(credentialFile, 'utf8'))
    const me = await fetch(`${origin}/api/v1/auth/me`, { headers: { Authorization: `Bearer ${token}` } })
    assert.ok(me.ok)
    const user = (await me.json()).data
    const adminContext = await browser.newContext({ locale: 'zh-CN' })
    await adminContext.addInitScript(({ token, user }) => {
      localStorage.setItem('auth_token', token)
      localStorage.setItem('auth_user', JSON.stringify(user))
      localStorage.setItem('sub2api_locale', 'zh')
      localStorage.setItem(`admin_guide_${user.id}_admin_v4_interactive`, 'true')
    }, { token, user })
    const adminPage = await adminContext.newPage()
    adminPage.on('pageerror', error => report.errors.push(error.message))
    for (const width of [1440, 390]) {
      await adminPage.setViewportSize({ width, height: 960 })
      for (const path of ['/admin/accounts', '/admin/groups', '/keys', '/admin/redeem']) {
        try {
          await capture(adminPage, path, `${path.slice(1).replaceAll('/', '-')}-${width}`)
          assert.equal(new URL(adminPage.url()).pathname, path, `Authenticated ${path} was redirected`)
        } catch (error) { report.failures.push(error.message) }
      }
    }
    await adminContext.close()
  }
  assert.deepEqual(report.errors, [], 'Browser runtime errors')
  assert.deepEqual(report.failures, [], 'Browser layout failures')
  report.passed = true
} catch (error) {
  report.failures.push(error.message)
  process.exitCode = 1
} finally {
  await browser.close()
  writeFileSync(join(directory, 'browser-report.json'), JSON.stringify(report, null, 2))
  console.log(JSON.stringify(report))
}
