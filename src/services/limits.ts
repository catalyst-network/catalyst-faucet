import type Redis from "ioredis";
import { createHash, randomBytes } from "crypto";

const PAUSED_KEY = "faucet:paused";

function cooldownAddrKey(address: string) {
  return `faucet:cooldown:addr:${address.toLowerCase()}`;
}
function cooldownIpKey(ipHash: string) {
  return `faucet:cooldown:ip:${ipHash}`;
}
function cooldownAsnKey(asn: number) {
  return `faucet:cooldown:asn:${asn}`;
}
function cooldownCountryKey(country: string) {
  return `faucet:cooldown:country:${country.toUpperCase()}`;
}
function lockAddrKey(address: string) {
  return `faucet:lock:addr:${address.toLowerCase()}`;
}
function lockIpKey(ipHash: string) {
  return `faucet:lock:ip:${ipHash}`;
}
function lockAsnKey(asn: number) {
  return `faucet:lock:asn:${asn}`;
}
function lockCountryKey(country: string) {
  return `faucet:lock:country:${country.toUpperCase()}`;
}

const RELEASE_LOCK_LUA = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
else
  return 0
end
`;

export type LimitsService = ReturnType<typeof createLimitsService>;

export function createLimitsService(
  redis: Redis,
  opts: { cooldownMs: number; globalRpm: number; ipHashSalt: string },
) {
  const { cooldownMs, globalRpm, ipHashSalt } = opts;

  function hashIp(ip: string): string {
    return createHash("sha256").update(`${ipHashSalt}:${ip}`).digest("hex");
  }

  async function isPaused(): Promise<boolean> {
    return (await redis.get(PAUSED_KEY)) === "1";
  }

  async function setPaused(paused: boolean): Promise<void> {
    if (paused) await redis.set(PAUSED_KEY, "1");
    else await redis.del(PAUSED_KEY);
  }

  async function checkGlobalLimitOrThrow(): Promise<void> {
    const minute = Math.floor(Date.now() / 60_000);
    const key = `faucet:global:min:${minute}`;
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, 70);
    if (count > globalRpm) {
      throw Object.assign(new Error("Rate limit exceeded"), { statusCode: 429 });
    }
  }

  async function getCooldown(params: {
    address: string;
    ipHash: string;
    asn?: number | null;
    country?: string | null;
  }): Promise<{
    eligible: boolean;
    nextEligibleAtMs: number;
  }> {
    const now = Date.now();
    const keys = [
      cooldownAddrKey(params.address),
      cooldownIpKey(params.ipHash),
      ...(params.asn != null ? [cooldownAsnKey(params.asn)] : []),
      ...(params.country ? [cooldownCountryKey(params.country)] : []),
    ];
    const ttls = await Promise.all(keys.map((k) => redis.pttl(k)));
    const ttlMs = Math.max(...ttls.map((t) => (t > 0 ? t : 0)));
    return { eligible: ttlMs <= 0, nextEligibleAtMs: now + ttlMs };
  }

  async function startCooldown(params: {
    address: string;
    ipHash: string;
    asn?: number | null;
    country?: string | null;
    nowMs: number;
  }): Promise<void> {
    const val = String(params.nowMs);
    const multi = redis
      .multi()
      .set(cooldownAddrKey(params.address), val, "PX", cooldownMs)
      .set(cooldownIpKey(params.ipHash), val, "PX", cooldownMs);
    if (params.asn != null) multi.set(cooldownAsnKey(params.asn), val, "PX", cooldownMs);
    if (params.country) multi.set(cooldownCountryKey(params.country), val, "PX", cooldownMs);
    await multi.exec();
  }

  async function acquireLocksOrThrow(params: {
    address: string;
    ipHash: string;
    asn?: number | null;
    country?: string | null;
  }) {
    const token = randomBytes(16).toString("hex");
    const lockKeys = [
      lockAddrKey(params.address),
      lockIpKey(params.ipHash),
      ...(params.asn != null ? [lockAsnKey(params.asn)] : []),
      ...(params.country ? [lockCountryKey(params.country)] : []),
    ];

    const lockMs = 60_000;
    const acquired: string[] = [];
    for (const key of lockKeys) {
      const ok = await redis.set(key, token, "PX", lockMs, "NX");
      if (ok !== "OK") {
        await Promise.allSettled(acquired.map((k) => redis.eval(RELEASE_LOCK_LUA, 1, k, token)));
        throw Object.assign(new Error("Claim already in progress"), { statusCode: 429 });
      }
      acquired.push(key);
    }

    return {
      async release() {
        await Promise.allSettled(acquired.map((k) => redis.eval(RELEASE_LOCK_LUA, 1, k, token)));
      },
    };
  }

  return {
    hashIp,
    isPaused,
    setPaused,
    checkGlobalLimitOrThrow,
    getCooldown,
    startCooldown,
    acquireLocksOrThrow,
  };
}

