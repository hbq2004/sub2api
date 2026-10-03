import { readFile } from 'node:fs/promises'

const defaultPolicy = new URL('./upstream-pool-policy.json', import.meta.url)

export async function assertLegacySyncAllowed(path = defaultPolicy) {
  let policy
  try { policy = JSON.parse(await readFile(path, 'utf8')) }
  catch (error) {
    throw new Error('Cannot read upstream pool ownership policy; sync is blocked')
  }
  if (policy.mode !== 'legacy-copy' || policy.legacy_copy_sync !== 'enabled') {
    const error = new Error('个人本地账号池与客户云端账号池按独立模式管理，复制同步已停用。转移账号需先停用源实例的调度和令牌刷新，请按 deploy/RELEASE_AND_RUNTIME_CN.md 操作。')
    error.code = 'ACCOUNT_POOL_TRANSFER_REQUIRED'
    throw error
  }
}
