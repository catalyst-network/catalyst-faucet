import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import RedisMock from "ioredis-mock";
import { createLimitsService } from "../src/services/limits";

describe("limits", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-02-22T12:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("hashIp is deterministic and salted", async () => {
    const redis = new (RedisMock as any)();
    const limits = createLimitsService(redis, {
      cooldownMs: 24 * 60 * 60 * 1000,
      globalRpm: 60,
      ipHashSalt: "salt-1234567890123456",
    });

    const a = limits.hashIp("203.0.113.10");
    const b = limits.hashIp("203.0.113.10");
    const c = limits.hashIp("203.0.113.11");
    expect(a).toEqual(b);
    expect(a).not.toEqual(c);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
  });

  test("global rpm limit blocks after threshold", async () => {
    const redis = new (RedisMock as any)();
    const limits = createLimitsService(redis, {
      cooldownMs: 24 * 60 * 60 * 1000,
      globalRpm: 2,
      ipHashSalt: "salt-1234567890123456",
    });

    await limits.checkGlobalLimitOrThrow();
    await limits.checkGlobalLimitOrThrow();
    await expect(limits.checkGlobalLimitOrThrow()).rejects.toMatchObject({ statusCode: 429 });
  });

  test("cooldown prevents repeat claims for address or IP", async () => {
    const redis = new (RedisMock as any)();
    const cooldownMs = 24 * 60 * 60 * 1000;
    const limits = createLimitsService(redis, {
      cooldownMs,
      globalRpm: 60,
      ipHashSalt: "salt-1234567890123456",
    });

    const ipHash = limits.hashIp("203.0.113.10");
    const address = "0x000000000000000000000000000000000000dEaD";

    const first = await limits.getCooldown({ address, ipHash });
    expect(first.eligible).toBe(true);

    await limits.startCooldown({ address, ipHash, nowMs: Date.now() });

    const second = await limits.getCooldown({ address, ipHash });
    expect(second.eligible).toBe(false);
    expect(second.nextEligibleAtMs).toBeGreaterThan(Date.now());

    vi.advanceTimersByTime(cooldownMs + 1);
    const third = await limits.getCooldown({ address, ipHash });
    expect(third.eligible).toBe(true);
  });

  test("lock prevents concurrent claims", async () => {
    const redis = new (RedisMock as any)();
    const limits = createLimitsService(redis, {
      cooldownMs: 24 * 60 * 60 * 1000,
      globalRpm: 60,
      ipHashSalt: "salt-1234567890123456",
    });

    const ipHash = limits.hashIp("203.0.113.10");
    const address = "0x000000000000000000000000000000000000dEaD";

    const lock = await limits.acquireLocksOrThrow({ address, ipHash });
    await expect(limits.acquireLocksOrThrow({ address, ipHash })).rejects.toMatchObject({ statusCode: 429 });
    await lock.release();
  });
});

