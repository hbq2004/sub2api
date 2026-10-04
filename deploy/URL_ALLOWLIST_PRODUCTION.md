# Outbound URL policy

The production Compose files enable `security.url_allowlist` and reject private
or link-local destinations and plain HTTP by default. The host list is an
operator-controlled inventory of provider endpoints. Add a custom provider only
after reviewing its DNS, redirects, proxy path, and credential handling; add its
exact hostname to `SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS`.

The checked-in default list covers the provider hosts used by this deployment:
OpenAI, Anthropic, Gemini/Cloud Code, Kimi/Moonshot, Zhipu, DeepSeek, MiniMax,
OpenCode, xAI/Grok, Ollama Cloud, TypeSafe, and Azure OpenAI. OAuth, payment,
and object-storage clients use their own endpoint validators or SDK policies.

Before a cloud rollout, record the resulting host count and reviewed custom
provider names in the release receipt. Do not set `allow_private_hosts=true` or
`allow_insecure_http=true` in the production `.env` as a compatibility shortcut.
