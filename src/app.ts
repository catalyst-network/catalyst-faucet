import Fastify, { type FastifyInstance } from "fastify";
import sensible from "@fastify/sensible";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";
import Redis from "ioredis";
import { PrismaClient } from "@prisma/client";
import { ethers } from "ethers";
import { randomUUID } from "crypto";

import type { AppConfig } from "./config";
import { createTurnstileVerifier } from "./services/turnstile";
import { createFaucetSender } from "./services/faucet";
import { createLimitsService } from "./services/limits";
import { createAdminAuth } from "./services/admin";

export type AppDeps = {
  config: AppConfig;
  redis: Redis;
  prisma: PrismaClient;
  provider: ethers.JsonRpcProvider;
  wallet: ethers.Wallet;
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

  const redis = new Redis(config.redisUrl, {
    maxRetriesPerRequest: 2,
    enableReadyCheck: true,
  });

  const prisma = new PrismaClient({
    datasources: { db: { url: config.databaseUrl } },
  });

  const provider = new ethers.JsonRpcProvider(config.rpcUrl, config.chainId);
  const wallet = new ethers.Wallet(config.faucetPrivateKey, provider);

  const verifyTurnstile = createTurnstileVerifier(config.turnstileSecretKey);
  const limits = createLimitsService(redis, {
    cooldownMs: config.cooldownMs,
    globalRpm: config.globalRpm,
    ipHashSalt: config.ipHashSalt,
  });
  const faucet = createFaucetSender({ provider, wallet, amountWei: config.faucetAmountWei });
  const adminAuth = createAdminAuth(config.adminToken);

  app.decorate("deps", { config, redis, prisma, provider, wallet } satisfies AppDeps);

  app.addHook("onClose", async () => {
    await Promise.allSettled([redis.quit(), prisma.$disconnect()]);
  });

  app.get("/health", async (req, reply) => {
    const start = Date.now();
    const [redisOk, dbOk, rpcBlockOk, rpcNetOk] = await Promise.allSettled([
      redis.ping(),
      prisma.$queryRaw`SELECT 1`,
      provider.getBlockNumber(),
      provider.getNetwork(),
    ]);

    const rpcNetworkMatches =
      rpcNetOk.status === "fulfilled" ? Number(rpcNetOk.value.chainId) === config.chainId : false;

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
    const balanceWei = await provider.getBalance(wallet.address);
    return {
      chainId: config.chainId,
      faucetAddress: wallet.address,
      amount: config.faucetAmount,
      cooldownHours: config.cooldownHours,
      balanceWei: balanceWei.toString(),
      balance: ethers.formatEther(balanceWei),
      explorerTxTemplate: config.explorerTxTemplate,
      paused: await limits.isPaused(),
    };
  });

  app.post("/v1/claim", async (req, reply) => {
    const body = req.body as unknown;
    if (!body || typeof body !== "object") throw app.httpErrors.badRequest("Invalid JSON body");
    const { address, captchaToken } = body as { address?: unknown; captchaToken?: unknown };
    if (typeof address !== "string" || typeof captchaToken !== "string") {
      throw app.httpErrors.badRequest("Body must include { address: string, captchaToken: string }");
    }

    if (await limits.isPaused()) throw app.httpErrors.serviceUnavailable("Faucet is paused");

    const normalized = faucet.normalizeAddress(address);

    // Global request rate limit (per minute)
    await limits.checkGlobalLimitOrThrow();

    const countryRaw = (req.headers["cf-ipcountry"] as string | undefined)?.trim();
    const asnRaw = (req.headers["cf-asn"] as string | undefined)?.trim();

    const country = config.enableCountryLimit && countryRaw ? countryRaw.toUpperCase() : null;
    const asn = config.enableAsnLimit && asnRaw ? Number.parseInt(asnRaw, 10) : null;

    if (config.enableCountryLimit && (!country || !/^[A-Z]{2}$/.test(country))) {
      throw app.httpErrors.badRequest("Missing/invalid cf-ipcountry header");
    }
    if (config.enableAsnLimit && (!Number.isFinite(asn) || (asn as number) <= 0)) {
      throw app.httpErrors.badRequest("Missing/invalid cf-asn header");
    }

    const clientIp = req.ip;
    const ipHash = limits.hashIp(clientIp);

    await verifyTurnstile({
      token: captchaToken,
      ip: clientIp,
      idempotencyKey: `${normalized}:${ipHash}`,
    });

    const lock = await limits.acquireLocksOrThrow({ address: normalized, ipHash, asn, country });
    try {
      const cooldown = await limits.getCooldown({ address: normalized, ipHash, asn, country });
      if (!cooldown.eligible) {
        return reply.code(429).send({
          error: "cooldown",
          nextEligibleAtMs: cooldown.nextEligibleAtMs,
        });
      }

      // DB fallback: protects against Redis restarts / key loss
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
        return reply.code(429).send({
          error: "cooldown",
          nextEligibleAtMs: recent.createdAt.getTime() + config.cooldownMs,
        });
      }

      const txHash = await faucet.sendTo(normalized);

      const sentAt = Date.now();
      const nextEligibleAtMs = sentAt + config.cooldownMs;

      await prisma.claim.create({
        data: {
          address: normalized,
          ipHash,
          amountWei: config.faucetAmountWei,
          txHash,
          country,
          asn,
          userAgent: (req.headers["user-agent"] as string | undefined) ?? null,
        },
      });

      await limits.startCooldown({ address: normalized, ipHash, asn, country, nowMs: sentAt });

      return {
        txHash,
        amount: config.faucetAmount,
        address: normalized,
        nextEligibleAtMs,
        txUrl: `${config.explorerBaseUrl}/tx/${txHash}`,
      };
    } finally {
      await lock.release();
    }
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

