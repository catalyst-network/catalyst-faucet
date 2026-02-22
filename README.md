# Catalyst Testnet Faucet (Backend)

Production-ready Catalyst **testnet-only** faucet backend.

- **Chain**: Catalyst testnet (EVM JSON-RPC)
- **Native token**: KAT (native transfer; not ERC-20 for MVP)
- **Explorer**: `https://explorer.catalystnet.org/tx/<txHash>`
- **ChainId allowlist**: only `0xbf8457c` (service refuses to start otherwise)

## Tech stack

- **Node.js + TypeScript**
- **Fastify** (HTTP + structured JSON logging)
- **ethers** (native value transfers)
- **Redis** (cooldowns + global request rate limiting + pause state)
- **Postgres + Prisma** (claim log + migrations)
- **Cloudflare Turnstile** (captcha)

## API

### `GET /health`

Checks **RPC + Redis + DB** health.

### `GET /v1/info`

Returns faucet settings for the UI.

```json
{
  "networkName": "Catalyst Testnet",
  "chainId": "0xbf8457c",
  "symbol": "KAT",
  "amount": "0.1",
  "cooldownSeconds": 86400
}
```

### `POST /v1/request`

Body:

```json
{ "address": "0x...", "turnstileToken": "token-from-turnstile" }
```

Returns:

```json
{ "txHash": "0x...", "nextEligibleAt": "2026-02-23T14:06:22.806Z" }
```

Notes:

- Enforces **per-address** and **per-IP** 24h cooldown (configurable via `COOLDOWN_HOURS`).
- Enforces **global requests/min** (`GLOBAL_RPM`, default 60).
- When `ENABLE_COUNTRY_LIMIT=true`, also enforces cooldown per country (requires `cf-ipcountry` header).
- When `ENABLE_ASN_LIMIT=true`, also enforces cooldown per ASN (requires `cf-asn` header).

### `POST /v1/claim` (compatibility alias)

Accepts either `{ address, captchaToken }` or `{ address, turnstileToken }` and returns the same response shape as `/v1/request`.

### Admin

All admin endpoints require an admin token via:

- `Authorization: Bearer <ADMIN_TOKEN>` or
- `x-admin-token: <ADMIN_TOKEN>`

#### `GET /v1/admin/claims`

Recent claims with optional filters:

- `address=0x...`
- `ipHash=<sha256>`
- `sinceMs=<epochMs>`
- `untilMs=<epochMs>`
- `limit=<1..200>`

#### `POST /v1/admin/pause`

Pauses claims (health/info still work).

#### `POST /v1/admin/unpause`

Unpauses claims.

## Environment variables

Required:

- **`RPC_URL`**: Catalyst testnet JSON-RPC URL
- **`CHAIN_ID`**: must be `0xbf8457c`
- **`FAUCET_PRIVATE_KEY`**: private key used to sign transfers
- **`FAUCET_AMOUNT`**: amount in whole tokens (decimal string), e.g. `0.1`
- **`COOLDOWN_HOURS`**: integer cooldown (hours), e.g. `24`
- **`REDIS_URL`**: e.g. `redis://redis:6379`
- **`DATABASE_URL`**: Postgres connection string
- **`TURNSTILE_SECRET_KEY`**: Cloudflare Turnstile secret
- **`ADMIN_TOKEN`**: shared secret for admin endpoints
- **`IP_HASH_SALT`**: long random string used to hash IPs before storing

Optional:

- **`PORT`** (default 8080)
- **`HOST`** (default `0.0.0.0`)
- **`GLOBAL_RPM`** (default 60)
- **`ENABLE_COUNTRY_LIMIT`** (default `false`)
- **`ENABLE_ASN_LIMIT`** (default `false`)

## Local development (no Docker)

You need Redis and Postgres running, then:

```bash
cp .env.example .env
# edit .env

npm install
npm run prisma:generate
npm run prisma:migrate:dev
npm run dev
```

## Docker Compose

```bash
cp .env.example .env
# edit .env (use the compose hostnames: redis, postgres)

docker compose up -d --build
```

The container runs `prisma migrate deploy` on startup.

## Threat model / abuse mitigation

### What we’re defending against

- **High-volume draining**: bots requesting repeatedly to drain faucet balance
- **Sybil attacks**: many addresses controlled by one attacker
- **IP rotation / proxy abuse**: multiple claims via changing IPs
- **Service overload**: request floods affecting availability
- **Misconfiguration**: accidentally running against non-testnet

### Mitigations implemented

- **Captcha (Turnstile)**: blocks basic automation before any on-chain action.
- **Per-address cooldown**: Redis cooldown key prevents repeat claims from the same address for `COOLDOWN_HOURS`.
- **Per-IP cooldown (hashed IP only)**: only a **salted SHA-256 hash** of the client IP is stored in Redis/DB.
- **Optional per-country / per-ASN cooldown**: when enabled, the service also rate-limits per `cf-ipcountry` / `cf-asn`.
  - Best used behind Cloudflare (or an edge that provides equivalent headers).
- **Global RPM limit**: caps total `POST /v1/claim` volume per minute.
- **DB fallback checks**: even if Redis keys are lost (restart/flush), the service checks recent claims in Postgres before sending.
- **Pause switch**: admin can pause claims quickly during abuse or wallet issues.
- **ChainId allowlist**: service refuses to start unless `CHAIN_ID` matches Catalyst testnet.
- **Structured logs with request id**: every request returns `x-request-id` and logs are JSON for correlation and incident response.

### Remaining considerations

- Put the faucet behind a reverse proxy/WAF (Cloudflare recommended) for additional bot filtering.
- Keep the faucet key in a secret manager; rotate if exposed.
- Consider adding allow/deny lists (countries/ASNs) and monitoring/alerting as you scale.

