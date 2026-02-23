import Fastify, { type FastifyInstance } from "fastify";
import sensible from "@fastify/sensible";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";
import Redis from "ioredis";
import { PrismaClient } from "@prisma/client";
import { randomUUID } from "crypto";

import type { AppConfig } from "./config";
import { ApiError, apiError } from "./errors";
import { createTurnstileVerifier } from "./services/turnstile";
import { createFaucetSender } from "./services/faucet";
import { createLimitsService } from "./services/limits";
import { createAdminAuth } from "./services/admin";
import { createCatalystRpcClient } from "./services/catalystRpc";

export type AppDeps = {
  config: AppConfig;
  redis: Redis;
  prisma: PrismaClient;
  rpc: ReturnType<typeof createCatalystRpcClient>;
};

export async function buildApp(config: AppConfig): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL ?? "info",
      redact: ["req.headers.authorization", "req.headers.cookie"],
    },
    trustProxy: true,
    genReqId: (req) => {
      const incoming = (req.headers["x-request-id"] as string | undefined)?.trim();
      return incoming && incoming.length > 0 ? incoming : randomUUID();
    },
  });

  await app.register(sensible);
  await app.register(helmet);
  await app.register(cors, { origin: true, credentials: false });

  app.addHook("onRequest", async (req, reply) => {
    reply.header("x-request-id", req.id);
  });

  app.setErrorHandler(async (err, req, reply) => {
    const statusCode = (err as any).statusCode && Number.isFinite((err as any).statusCode) ? (err as any).statusCode : 500;

    if (err instanceof ApiError) {
      if (err.statusCode === 429 && err.code === "COOLDOWN_ACTIVE") {
        const now = Date.now();
        const nextEligibleAtMs =
          typeof err.meta?.nextEligibleAtMs === "number" ? (err.meta.nextEligibleAtMs as number) : now + 60_000;
        const retryAfterSeconds =
          typeof err.meta?.retryAfterSeconds === "number"
            ? (err.meta.retryAfterSeconds as number)
            : Math.max(1, Math.ceil((nextEligibleAtMs - now) / 1000));

        reply.header("retry-after", String(retryAfterSeconds));
        return reply.code(429).send({
          error: {
            code: err.code,
            message: err.message,
            ...(err.details ? { details: err.details } : {}),
          },
          nextEligibleAt: new Date(nextEligibleAtMs).toISOString(),
          retryAfterSeconds,
        });
      }

      return reply.code(err.statusCode).send({
        error: {
          code: err.code,
          message: err.message,
          ...(err.details ? { details: err.details } : {}),
        },
      });
    }

    // Fastify content-type / JSON body parse errors (keep user-facing message clear)
    const errCode = (err as any)?.code as string | undefined;
    if (
      errCode === "FST_ERR_CTP_INVALID_MEDIA_TYPE" ||
      errCode === "FST_ERR_CTP_EMPTY_JSON_BODY" ||
      errCode === "FST_ERR_CTP_INVALID_JSON_BODY"
    ) {
      return reply.code(400).send({
        error: {
          code: "INVALID_REQUEST",
          message: "Invalid JSON request body",
          details: { hint: "Send Content-Type: application/json with a JSON object body." },
        },
      });
    }

    if ((err as any).validation) {
      return reply.code(400).send({
        error: { code: "INVALID_REQUEST", message: "Invalid address/body" },
      });
    }

    req.log.error({ err }, "Unhandled error");
    return reply.code(statusCode).send({
      error: { code: "INTERNAL_ERROR", message: "Internal server error" },
    });
  });

  const redis = new Redis(config.redisUrl, {
    maxRetriesPerRequest: 2,
    enableReadyCheck: true,
  });

  const prisma = new PrismaClient({
    datasources: { db: { url: config.databaseUrl } },
  });

  const rpc = createCatalystRpcClient(config.rpcUrl);

  const verifyTurnstile = createTurnstileVerifier(config.turnstileSecretKey);
  const limits = createLimitsService(redis, {
    cooldownMs: config.cooldownMs,
    globalRpm: config.globalRpm,
    ipHashSalt: config.ipHashSalt,
  });
  const faucet = createFaucetSender({
    rpcUrl: config.rpcUrl,
    chainId: config.chainId,
    genesisHash: config.genesisHash,
    faucetPrivateKeyHex: config.faucetPrivateKeyHex,
    amountUnits: config.faucetAmountUnits,
  });
  const adminAuth = createAdminAuth(config.adminToken);

  app.decorate("deps", { config, redis, prisma, rpc } satisfies AppDeps);

  app.addHook("onClose", async () => {
    await Promise.allSettled([redis.quit(), prisma.$disconnect()]);
  });

  app.get("/health", async (req, reply) => {
    const start = Date.now();
    const [redisOk, dbOk, rpcInfoOk, rpcBlockOk] = await Promise.allSettled([
      redis.ping(),
      prisma.$queryRaw`SELECT 1`,
      rpc.getSyncInfo(),
      rpc.blockNumber(),
    ]);

    const rpcNetworkMatches =
      rpcInfoOk.status === "fulfilled"
        ? rpcInfoOk.value.chain_id.trim().toLowerCase() === `0x${config.chainId.toString(16)}` &&
          rpcInfoOk.value.genesis_hash.trim().toLowerCase() === config.genesisHash.toLowerCase()
        : false;
    const rpcOk = rpcBlockOk.status === "fulfilled" && rpcNetworkMatches;
    const ok = redisOk.status === "fulfilled" && dbOk.status === "fulfilled" && rpcOk;

    return reply.code(ok ? 200 : 503).send({
      ok,
      latencyMs: Date.now() - start,
      redis: redisOk.status === "fulfilled",
      db: dbOk.status === "fulfilled",
      rpc: rpcOk,
      rpcNetworkMatches,
      requestId: req.id,
    });
  });

  app.get("/v1/info", async () => {
    return {
      networkName: "Catalyst Testnet",
      chainId: `0x${config.chainId.toString(16)}`,
      symbol: "KAT",
      amount: config.faucetAmount,
      cooldownSeconds: Math.floor(config.cooldownMs / 1000),
    };
  });

  async function performRequest(params: { address: string; turnstileToken: string; ip: string; headers: Record<string, unknown> }) {
    if (await limits.isPaused()) {
      throw apiError({
        statusCode: 503,
        code: "UPSTREAM_UNAVAILABLE",
        message: "Faucet is temporarily unavailable",
        details: { hint: "try again later" },
      });
    }

    const normalized = faucet.normalizeAddress(params.address);

    await limits.checkGlobalLimitOrThrow();

    const countryRaw = (params.headers["cf-ipcountry"] as string | undefined)?.trim();
    const asnRaw = (params.headers["cf-asn"] as string | undefined)?.trim();

    const country = config.enableCountryLimit && countryRaw ? countryRaw.toUpperCase() : null;
    const asn = config.enableAsnLimit && asnRaw ? Number.parseInt(asnRaw, 10) : null;

    if (config.enableCountryLimit && (!country || !/^[A-Z]{2}$/.test(country))) {
      throw apiError({ statusCode: 400, code: "INVALID_REQUEST", message: "Invalid address/body" });
    }
    if (config.enableAsnLimit && (!Number.isFinite(asn) || (asn as number) <= 0)) {
      throw apiError({ statusCode: 400, code: "INVALID_REQUEST", message: "Invalid address/body" });
    }

    const ipHash = limits.hashIp(params.ip);

    await verifyTurnstile({
      token: params.turnstileToken,
      ip: params.ip,
      idempotencyKey: `${normalized}:${ipHash}`,
    });

    const lock = await limits.acquireLocksOrThrow({ address: normalized, ipHash, asn, country });
    try {
      const cooldown = await limits.getCooldown({ address: normalized, ipHash, asn, country });
      if (!cooldown.eligible) {
        const now = Date.now();
        const retryAfterSeconds = Math.max(1, Math.ceil((cooldown.nextEligibleAtMs - now) / 1000));
        throw apiError({
          statusCode: 429,
          code: "COOLDOWN_ACTIVE",
          message: "Cooldown active. Try again later.",
          meta: { nextEligibleAtMs: cooldown.nextEligibleAtMs, retryAfterSeconds },
        });
      }

      const now = Date.now();
      const since = new Date(now - config.cooldownMs);
      const or: Array<Record<string, unknown>> = [{ address: normalized }, { ipHash }];
      if (asn != null) or.push({ asn });
      if (country) or.push({ country });
      const recent = await prisma.claim.findFirst({
        where: {
          createdAt: { gte: since },
          OR: or,
        },
        orderBy: { createdAt: "desc" },
      });
      if (recent) {
        const nextEligibleAtMs = recent.createdAt.getTime() + config.cooldownMs;
        const retryAfterSeconds = Math.max(1, Math.ceil((nextEligibleAtMs - now) / 1000));
        throw apiError({
          statusCode: 429,
          code: "COOLDOWN_ACTIVE",
          message: "Cooldown active. Try again later.",
          meta: { nextEligibleAtMs, retryAfterSeconds },
        });
      }

      let txHash: string;
      try {
        txHash = await faucet.sendTo(normalized);
      } catch {
        throw apiError({
          statusCode: 503,
          code: "UPSTREAM_UNAVAILABLE",
          message: "Faucet is temporarily unavailable",
          details: { hint: "try again later" },
        });
      }

      const sentAt = Date.now();
      const nextEligibleAtMs = sentAt + config.cooldownMs;

      await prisma.claim.create({
        data: {
          address: normalized,
          ipHash,
          amountWei: config.faucetAmountUnits,
          txHash,
          country,
          asn,
          userAgent: (params.headers["user-agent"] as string | undefined) ?? null,
        },
      });

      await limits.startCooldown({ address: normalized, ipHash, asn, country, nowMs: sentAt });

      return { txHash, nextEligibleAtMs };
    } finally {
      await lock.release();
    }
  }

  app.post("/v1/request", async (req) => {
    const body = req.body as unknown;
    if (!body || typeof body !== "object") {
      throw apiError({
        statusCode: 400,
        code: "INVALID_REQUEST",
        message: "Expected a JSON object body",
        details: { hint: 'POST JSON like {"address":"0x...","turnstileToken":"..."}' },
      });
    }
    const rec = body as Record<string, unknown>;
    const address = typeof rec.address === "string" ? rec.address : undefined;
    const token =
      (typeof rec.turnstileToken === "string" && rec.turnstileToken) ||
      (typeof rec.cfTurnstileResponse === "string" && rec.cfTurnstileResponse) ||
      (typeof rec.captchaToken === "string" && rec.captchaToken) ||
      undefined;
    if (typeof address !== "string" || typeof token !== "string") {
      throw apiError({
        statusCode: 400,
        code: "INVALID_REQUEST",
        message: "Missing required fields",
        details: {
          required: ["address", "turnstileToken"],
          acceptedTokenFields: ["turnstileToken", "cfTurnstileResponse", "captchaToken"],
          receivedKeys: Object.keys(rec).sort(),
          receivedTypes: {
            address: typeof rec.address,
            turnstileToken: typeof rec.turnstileToken,
            cfTurnstileResponse: typeof rec.cfTurnstileResponse,
            captchaToken: typeof rec.captchaToken,
          },
        },
      });
    }

    const res = await performRequest({
      address,
      turnstileToken: token,
      ip: req.ip,
      headers: req.headers as unknown as Record<string, unknown>,
    });

    return { txHash: res.txHash, nextEligibleAt: new Date(res.nextEligibleAtMs).toISOString() };
  });

  // Backwards-compatible alias (accepts either captchaToken or turnstileToken)
  app.post("/v1/claim", async (req) => {
    const body = req.body as unknown;
    if (!body || typeof body !== "object") {
      throw apiError({
        statusCode: 400,
        code: "INVALID_REQUEST",
        message: "Expected a JSON object body",
        details: { hint: 'POST JSON like {"address":"0x...","turnstileToken":"..."}' },
      });
    }
    const rec = body as Record<string, unknown>;
    const address = typeof rec.address === "string" ? rec.address : undefined;
    const token =
      (typeof rec.turnstileToken === "string" && rec.turnstileToken) ||
      (typeof rec.cfTurnstileResponse === "string" && rec.cfTurnstileResponse) ||
      (typeof rec.captchaToken === "string" && rec.captchaToken) ||
      undefined;
    if (typeof address !== "string" || typeof token !== "string") {
      throw apiError({
        statusCode: 400,
        code: "INVALID_REQUEST",
        message: "Missing required fields",
        details: {
          required: ["address", "turnstileToken"],
          acceptedTokenFields: ["turnstileToken", "cfTurnstileResponse", "captchaToken"],
          receivedKeys: Object.keys(rec).sort(),
          receivedTypes: {
            address: typeof rec.address,
            turnstileToken: typeof rec.turnstileToken,
            cfTurnstileResponse: typeof rec.cfTurnstileResponse,
            captchaToken: typeof rec.captchaToken,
          },
        },
      });
    }

    const res = await performRequest({
      address,
      turnstileToken: token,
      ip: req.ip,
      headers: req.headers as unknown as Record<string, unknown>,
    });

    return { txHash: res.txHash, nextEligibleAt: new Date(res.nextEligibleAtMs).toISOString() };
  });

  app.get("/v1/admin/claims", async (req) => {
    adminAuth.assertAdmin(req);
    const q = req.query as Record<string, unknown>;
    const address = typeof q.address === "string" ? q.address : undefined;
    const ipHash = typeof q.ipHash === "string" ? q.ipHash : undefined;
    const limitRaw = typeof q.limit === "string" ? Number(q.limit) : undefined;
    const limit = Math.min(200, Math.max(1, limitRaw ?? 50));
    const sinceMs = typeof q.sinceMs === "string" ? Number(q.sinceMs) : undefined;
    const untilMs = typeof q.untilMs === "string" ? Number(q.untilMs) : undefined;

    const where: Record<string, unknown> = {};
    if (address) where.address = faucet.normalizeAddress(address);
    if (ipHash) where.ipHash = ipHash;
    if (Number.isFinite(sinceMs) || Number.isFinite(untilMs)) {
      where.createdAt = {
        ...(Number.isFinite(sinceMs) ? { gte: new Date(sinceMs as number) } : {}),
        ...(Number.isFinite(untilMs) ? { lte: new Date(untilMs as number) } : {}),
      };
    }

    const claims = await prisma.claim.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: limit,
    });

    return {
      claims: claims.map((c) => ({
        id: c.id,
        address: c.address,
        ipHash: c.ipHash,
        amountWei: c.amountWei.toString(),
        txHash: c.txHash,
        txUrl: `${config.explorerBaseUrl}/tx/${c.txHash}`,
        country: c.country,
        asn: c.asn,
        createdAt: c.createdAt.toISOString(),
      })),
    };
  });

  app.post("/v1/admin/pause", async (req) => {
    adminAuth.assertAdmin(req);
    await limits.setPaused(true);
    return { paused: true };
  });

  app.post("/v1/admin/unpause", async (req) => {
    adminAuth.assertAdmin(req);
    await limits.setPaused(false);
    return { paused: false };
  });

  return app;
}

declare module "fastify" {
  interface FastifyInstance {
    deps: AppDeps;
  }
}

