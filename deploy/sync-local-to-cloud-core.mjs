import { createHash } from 'node:crypto'

const GROUP_FIELDS = [
  'name', 'description', 'platform', 'rate_multiplier', 'is_exclusive', 'status',
  'subscription_type', 'daily_limit_usd', 'weekly_limit_usd', 'monthly_limit_usd',
  'long_context_pricing_enabled', 'model_pricing', 'allow_image_generation',
  'allow_batch_image_generation', 'image_rate_independent', 'image_rate_multiplier',
  'batch_image_discount_multiplier', 'batch_image_hold_multiplier',
  'video_rate_independent', 'video_rate_multiplier', 'peak_rate_enabled',
  'peak_start', 'peak_end', 'peak_rate_multiplier', 'profit_control_enabled',
  'profit_min_margin', 'profit_safety_buffer', 'image_price_1k', 'image_price_2k',
  'image_price_4k', 'video_price_480p', 'video_price_720p', 'video_price_1080p',
  'video_model_prices', 'web_search_price_per_call', 'search_price_per_1k',
  'audio_realtime_price_per_min', 'audio_tts_price_per_million_chars',
  'audio_stt_price_per_hour', 'claude_code_only', 'allow_messages_dispatch',
  'allow_live', 'force_openai_fast', 'free_openai_fast', 'require_oauth_only',
  'require_privacy_set', 'default_mapped_model', 'messages_dispatch_model_config',
  'model_allowlist', 'codex_models_manifest_config', 'model_routing',
  'model_routing_enabled', 'mcp_xml_inject',
  'supported_model_scopes', 'rpm_limit', 'max_reasoning_effort',
  'max_reasoning_effort_over_limit', 'reasoning_effort_mappings'
]

const CLOUD_RUNTIME_EXTRA = new Set([
  'quota_used', 'quota_daily_used', 'quota_daily_start', 'quota_weekly_used',
  'quota_weekly_start', 'quota_daily_reset_at', 'quota_weekly_reset_at',
  'grok_billing_snapshot', 'grok_usage_snapshot', 'upstream_billing_probe',
  'upstream_billing_probe_enabled', 'upstream_billing_rate_sync_enabled',
  'ollama_cloud_usage_session', 'ollama_cloud_usage_snapshot',
  'ollama_cloud_usage_auto_refresh', 'opencode_go_usage_auto_refresh',
  'opencode_go_usage_snapshot', 'codex_auto_reset_credit_state',
  'duplicate_operation_id', 'antigravity_credits_overages', 'model_rate_limits',
  'session_window_utilization', 'passive_usage_7d_utilization',
  'passive_usage_7d_reset', 'passive_usage_7d_oi_utilization',
  'passive_usage_7d_oi_reset', 'passive_usage_sampled_at',
  'openai_responses_supported', 'openai_compact_supported',
  'openai_compact_checked_at', 'openai_compact_last_status',
  'openai_compact_last_error', 'antigravity_force_token_refresh',
  'antigravity_force_token_refresh_at', 'antigravity_force_token_refresh_reason',
  'drive_storage_limit', 'drive_storage_usage', 'drive_tier_updated_at',
  'codex_fingerprint_seed', 'codex_primary_used_percent',
  'codex_primary_reset_after_seconds', 'codex_primary_window_minutes',
  'codex_secondary_used_percent', 'codex_secondary_reset_after_seconds',
  'codex_secondary_window_minutes', 'codex_primary_over_secondary_percent',
  'codex_usage_updated_at', 'codex_5h_used_percent',
  'codex_5h_reset_after_seconds', 'codex_5h_window_minutes',
  'codex_5h_reset_at', 'codex_7d_used_percent',
  'codex_7d_reset_after_seconds', 'codex_7d_window_minutes',
  'codex_7d_reset_at', 'codex_credits_snapshot',
  'codex_reset_credit_snapshot', 'upstream_model_metadata', 'privacy_mode'
])

const OAUTH_RUNTIME_CREDENTIALS = new Set([
  'access_token', 'refresh_token', 'id_token', 'expires_at',
  'plan_type', 'subscription_expires_at'
])

function partition(record = {}, excluded) {
  const stable = {}
  const runtime = {}
  for (const [key, value] of Object.entries(record ?? {})) {
    (excluded.has(key) ? runtime : stable)[key] = value
  }
  return { stable, runtime }
}

export function portableAccountExtra(extra = {}) {
  return partition(extra, CLOUD_RUNTIME_EXTRA).stable
}

function comparableConfig(kind, config) {
  if (kind !== 'accounts' || config.type !== 'oauth') return config
  const extra = { ...config.extra }
  if (config.platform === 'openai') {
    if (extra.auto_reset_credit_enabled === false) delete extra.auto_reset_credit_enabled
    if (extra.auto_reset_credit_5h_threshold === 1) delete extra.auto_reset_credit_5h_threshold
    if (extra.auto_reset_credit_7d_threshold === 1) delete extra.auto_reset_credit_7d_threshold
  }
  return { ...config,
    credentials: partition(config.credentials, OAUTH_RUNTIME_CREDENTIALS).stable,
    extra }
}

export function configFingerprint(kind, config) {
  return fingerprint(comparableConfig(kind, config))
}

export function isSyncTransition(kind, current, before, intended) {
  const observed = comparableConfig(kind, current)
  const previous = comparableConfig(kind, before)
  const next = comparableConfig(kind, intended)
  // An API can persist account settings and then fail binding its groups.
  // Accept that intermediate state only when every field is one of the two
  // values owned by this sync; a third value indicates an independent edit.
  return [...new Set([...Object.keys(observed), ...Object.keys(previous),
    ...Object.keys(next)])].every(field => {
    const hash = fingerprint(observed[field])
    return hash === fingerprint(previous[field]) || hash === fingerprint(next[field])
  })
}

function changedFields(kind, source, remote) {
  const left = comparableConfig(kind, source)
  const right = comparableConfig(kind, remote)
  const fields = new Set([...Object.keys(left), ...Object.keys(right)])
  return [...fields].flatMap(field => {
    if (fingerprint(left[field]) === fingerprint(right[field])) return []
    if (!['credentials', 'extra'].includes(field) || !left[field] || !right[field]) {
      return [field]
    }
    const keys = new Set([...Object.keys(left[field]), ...Object.keys(right[field])])
    return [...keys].filter(key => fingerprint(left[field][key]) !==
      fingerprint(right[field][key])).map(key =>
      /^[A-Za-z0-9_]{1,64}$/.test(key) ? `${field}.${key}` : field)
  })
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]))
  }
  return value
}

export function fingerprint(value) {
  return createHash('sha256').update(JSON.stringify(canonical(value)) ?? 'undefined').digest('hex')
}

function pick(record, fields) {
  return Object.fromEntries(fields.filter(field => record[field] !== undefined).map(field => [field, record[field]]))
}

function uniqueIndex(items, identity, label) {
  const index = new Map()
  for (const item of items) {
    const key = identity(item)
    if (index.has(key)) throw new Error(`Duplicate ${label} identity: ${key}`)
    index.set(key, item)
  }
  return index
}

export const groupIdentity = group => `${group.platform}\u0000${group.name}`
export const accountIdentity = account => `${account.platform}\u0000${account.type}\u0000${account.name}`

function assertPortableGroup(group) {
  if (group.fallback_group_id || group.fallback_group_id_on_invalid_request ||
      Object.values(group.model_routing ?? {}).some(ids => ids.length) ||
      group.codex_models_manifest_config?.account_ids?.length) {
    throw new Error(`Group ${group.name} has cross-instance ID references; sync is stopped`)
  }
}

export function normalizeSnapshot({ groups, accounts, accountData, keys }) {
  const groupsByID = new Map(groups.map(group => [group.id, group]))
  const accountList = uniqueIndex(accounts, accountIdentity, 'account')
  const exported = uniqueIndex(accountData.accounts, accountIdentity, 'exported account')
  const normalizedGroups = groups.map(group => {
    assertPortableGroup(group)
    return { id: group.id, identity: groupIdentity(group), label: group.name,
      config: pick(group, GROUP_FIELDS) }
  })
  const normalizedAccounts = [...exported.values()].map(account => {
    const listed = accountList.get(accountIdentity(account))
    if (!listed) throw new Error(`Exported account ${account.name} is absent from account list`)
    const groupIdentities = (listed.group_ids ?? []).map(id => {
      const group = groupsByID.get(id)
      if (!group) throw new Error(`Account ${account.name} has an unknown group`)
      return groupIdentity(group)
    }).sort()
    return { id: listed.id, identity: accountIdentity(account), label: account.name,
      config: { name: account.name, notes: account.notes ?? null,
        platform: account.platform, type: account.type,
        credentials: account.credentials, extra: portableAccountExtra(account.extra),
        concurrency: account.concurrency, priority: account.priority,
        rate_multiplier: account.rate_multiplier ?? 1,
        expires_at: account.expires_at ?? null,
        auto_pause_on_expired: account.auto_pause_on_expired ?? true,
        load_factor: listed.load_factor ?? null,
        status: listed.status === 'inactive' ? 'inactive' : 'active',
        groups: groupIdentities },
      runtimeExtra: partition(account.extra, CLOUD_RUNTIME_EXTRA).runtime,
      localProxyIgnored: Boolean(account.proxy_key) }
  })
  const normalizedKeys = keys.map(key => {
    const group = key.group_id == null ? null : groupsByID.get(key.group_id)
    if (key.group_id != null && !group) throw new Error(`API Key ${key.name} has an unknown group`)
    return { id: key.id, identity: key.key, label: key.name,
      config: { key: key.key, name: key.name,
        group: group ? groupIdentity(group) : null,
        status: key.status === 'inactive' ? 'inactive' : 'active',
        ip_whitelist: key.ip_whitelist ?? [],
        ip_blacklist: key.ip_blacklist ?? [], quota: key.quota,
        expires_at: key.expires_at ?? null, rate_limit_5h: key.rate_limit_5h,
        rate_limit_1d: key.rate_limit_1d, rate_limit_7d: key.rate_limit_7d } }
  })
  return { groups: normalizedGroups, accounts: normalizedAccounts, keys: normalizedKeys,
    skippedShadows: accountData.skipped_shadows ?? 0 }
}

export function buildPlan(source, target, state = {}) {
  const plan = []
  for (const kind of ['groups', 'accounts', 'keys']) {
    const targets = uniqueIndex(target[kind], item => item.identity, kind)
    uniqueIndex(source[kind], item => item.identity, kind)
    for (const item of source[kind]) {
      const remote = targets.get(item.identity)
      const sourceHash = fingerprint(comparableConfig(kind, item.config))
      const remoteHash = remote && fingerprint(comparableConfig(kind, remote.config))
      const baseline = state[kind]?.[item.identity]
      let action = 'skip'
      if (!remote) action = 'create'
      else if (sourceHash !== remoteHash) {
        action = baseline && baseline.remoteHash === remoteHash ? 'update' : 'conflict'
      }
      const differences = remote && sourceHash !== remoteHash
        ? changedFields(kind, item.config, remote.config) : []
      const ignored = kind === 'accounts' && remote ? [
        ...(item.config.type === 'oauth' && fingerprint(partition(item.config.credentials,
          OAUTH_RUNTIME_CREDENTIALS).runtime) !== fingerprint(partition(
          remote.config.credentials, OAUTH_RUNTIME_CREDENTIALS).runtime)
          ? ['oauth_tokens'] : []),
        ...(fingerprint(item.runtimeExtra) !== fingerprint(remote.runtimeExtra)
          ? ['runtime_usage'] : [])
      ] : []
      plan.push({ kind, item, remote, action, sourceHash, remoteHash, differences, ignored })
    }
  }
  return plan
}

export function selectAccounts(snapshot, ids) {
  const requested = new Set(ids)
  if (requested.size !== ids.length || !requested.size) {
    throw new Error('Account selection requires distinct IDs')
  }
  const accounts = snapshot.accounts.filter(item => requested.has(item.id))
  for (const id of ids) {
    if (!accounts.some(item => item.id === id)) {
      throw new Error(`Local upstream account ${id} was not exported; check its ID and --include-oauth`)
    }
  }
  const requiredGroups = new Set(accounts.flatMap(item => item.config.groups))
  const groups = snapshot.groups.filter(item => requiredGroups.has(item.identity))
  if (groups.length !== requiredGroups.size) {
    throw new Error('Selected upstream accounts reference a missing group')
  }
  return { ...snapshot, groups, accounts, keys: [], skippedOAuth: 0 }
}

export function selectAccount(snapshot, id) {
  return selectAccounts(snapshot, [id])
}

export function buildState(source, target) {
  const state = { version: 1, groups: {}, accounts: {}, keys: {} }
  for (const kind of ['groups', 'accounts', 'keys']) {
    const targets = uniqueIndex(target[kind], item => item.identity, kind)
    for (const item of source[kind]) {
      const remote = targets.get(item.identity)
      if (remote && fingerprint(comparableConfig(kind, item.config)) ===
          fingerprint(comparableConfig(kind, remote.config))) {
        state[kind][item.identity] = {
          remoteHash: fingerprint(comparableConfig(kind, remote.config)) }
      }
    }
  }
  return state
}

export function groupPayload(config) {
  return { ...config, status: config.status }
}

export function accountPayload(config, remoteGroups, remote) {
  let credentials = config.credentials
  let extra = config.extra
  if (remote) {
    extra = fingerprint(config.extra) === fingerprint(remote.config.extra)
      ? undefined : { ...remote.runtimeExtra, ...config.extra }
    if (config.type === 'oauth') {
      const stableLocal = partition(config.credentials, OAUTH_RUNTIME_CREDENTIALS).stable
      const stableRemote = partition(remote.config.credentials, OAUTH_RUNTIME_CREDENTIALS).stable
      credentials = fingerprint(stableLocal) === fingerprint(stableRemote) ? undefined : {
        ...stableLocal,
        ...Object.fromEntries(Object.entries(remote.config.credentials ?? {}).filter(([key]) =>
          OAUTH_RUNTIME_CREDENTIALS.has(key) &&
          !['access_token', 'refresh_token', 'id_token'].includes(key)))
      }
    }
  }
  return { ...config, credentials, extra, groups: undefined,
    // The update API treats null pointers as omitted. Explicit zero/empty
    // values clear these settings instead of leaving the cloud value intact.
    ...(remote ? { expires_at: config.expires_at ?? 0,
      load_factor: config.load_factor ?? 0, notes: config.notes ?? '' } : {}),
    group_ids: config.groups.map(identity => {
      const group = remoteGroups.get(identity)
      if (!group) throw new Error(`Target group is missing: ${identity}`)
      return group.id
    }) }
}

export function keyPayload(config, remoteGroups) {
  const group = config.group && remoteGroups.get(config.group)
  if (config.group && !group) throw new Error(`Target group is missing: ${config.group}`)
  return { name: config.name,
    ip_whitelist: config.ip_whitelist, ip_blacklist: config.ip_blacklist,
    quota: config.quota, rate_limit_5h: config.rate_limit_5h,
    rate_limit_1d: config.rate_limit_1d, rate_limit_7d: config.rate_limit_7d,
    status: config.status, expires_at: config.expires_at ?? '' }
}
