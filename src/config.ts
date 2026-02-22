import { z } from "zod";
import { ethers } from "ethers";

const ALLOWED_CHAIN_IDS = new Set<number>([0xbf8457c]);

function parseChainId(input: string): number {
  const s = input.trim().toLowerCase();
  const n = s.startsWith("0x") ? Number.parseInt(s.slice(2), 16) : Number.parseInt(s, 10);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`Invalid CHAIN_ID: ${input}`);
  return n;
}

const envSchema = z.object({
  RPC_URL: z.string().url(),
  CHAIN_ID: z.string().min(1),
  FAUCET_PRIVATE_KEY: z.string().min(1),
  FAUCET_AMOUNT: z.string().min(1),
  COOLDOWN_HOURS: z.coerce.number().int().positive(),
  REDIS_URL: z.string().min(1),
  DATABASE_URL: z.string().min(1),
  TURNSTILE_SECRET_KEY: z.string().min(1),
  ADMIN_TOKEN: z.string().min(1),
  IP_HASH_SALT: z.string().min(16),
  // Optional: provide the expected genesis block hash (block 0) to verify the RPC
  // is pointing at the intended network when eth_chainId/net_version are unavailable.
  GENESIS_HASH: z.string().optional(),

  // Default to 8080 so the web UI can run on Next.js' default 3000 locally.
  PORT: z.coerce.number().int().positive().default(8080),
  HOST: z.string().default("0.0.0.0"),
  GLOBAL_RPM: z.coerce.number().int().positive().default(60),
  ENABLE_COUNTRY_LIMIT: z.coerce.boolean().default(false),
  ENABLE_ASN_LIMIT: z.coerce.boolean().default(false),
});

export type AppConfig = Readonly<{
  rpcUrl: string;
  chainId: number;
  faucetPrivateKey: string;
  faucetAmount: string;
  faucetAmountWei: bigint;
  cooldownHours: number;
  cooldownMs: number;
  redisUrl: string;
  databaseUrl: string;
  turnstileSecretKey: string;
  adminToken: string;
  ipHashSalt: string;
  genesisHash: string | null;
  explorerBaseUrl: string;
  explorerTxTemplate: string;
  port: number;
  host: string;
  globalRpm: number;
  enableCountryLimit: boolean;
  enableAsnLimit: boolean;
}>;

export function loadConfig(processEnv: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.parse(processEnv);

  const chainId = parseChainId(parsed.CHAIN_ID);
  if (!ALLOWED_CHAIN_IDS.has(chainId)) {
    throw new Error(
      `Refusing to start: CHAIN_ID=${parsed.CHAIN_ID} is not allowed for this faucet.`,
    );
  }

  let faucetAmountWei: bigint;
  try {
    faucetAmountWei = ethers.parseEther(parsed.FAUCET_AMOUNT);
  } catch {
    throw new Error(`Invalid FAUCET_AMOUNT (expected decimal tokens): ${parsed.FAUCET_AMOUNT}`);
  }

  const cooldownMs = parsed.COOLDOWN_HOURS * 60 * 60 * 1000;

  const explorerBaseUrl = "https://explorer.catalystnet.org";
  const explorerTxTemplate = `${explorerBaseUrl}/tx/<txHash>`;

  const genesisHashRaw = parsed.GENESIS_HASH?.trim();
  const genesisHash =
    genesisHashRaw && genesisHashRaw.length > 0 ? genesisHashRaw.toLowerCase() : null;
  if (genesisHash && !/^0x[0-9a-f]{64}$/.test(genesisHash)) {
    throw new Error(`Invalid GENESIS_HASH (expected 0x + 64 hex chars): ${parsed.GENESIS_HASH}`);
  }

  return {
    rpcUrl: parsed.RPC_URL,
    chainId,
    faucetPrivateKey: parsed.FAUCET_PRIVATE_KEY,
    faucetAmount: parsed.FAUCET_AMOUNT,
    faucetAmountWei,
    cooldownHours: parsed.COOLDOWN_HOURS,
    cooldownMs,
    redisUrl: parsed.REDIS_URL,
    databaseUrl: parsed.DATABASE_URL,
    turnstileSecretKey: parsed.TURNSTILE_SECRET_KEY,
    adminToken: parsed.ADMIN_TOKEN,
    ipHashSalt: parsed.IP_HASH_SALT,
    genesisHash,
    explorerBaseUrl,
    explorerTxTemplate,
    port: parsed.PORT,
    host: parsed.HOST,
    globalRpm: parsed.GLOBAL_RPM,
    enableCountryLimit: parsed.ENABLE_COUNTRY_LIMIT,
    enableAsnLimit: parsed.ENABLE_ASN_LIMIT,
  };
}

