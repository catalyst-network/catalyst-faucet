import { z } from "zod";
function isHex32(s: string): boolean {
  return /^0x[0-9a-f]{64}$/.test(s);
}

const ALLOWED_CHAIN_IDS = new Set<number>([0xbf8457c]);

function envBool(defaultValue: boolean) {
  return z.preprocess((v) => {
    if (v === undefined || v === null) return undefined;
    if (typeof v === "boolean") return v;
    if (typeof v === "number") return v !== 0;
    if (typeof v !== "string") return v;
    const s = v.trim().toLowerCase();
    if (s === "") return undefined;
    if (["1", "true", "t", "yes", "y", "on"].includes(s)) return true;
    if (["0", "false", "f", "no", "n", "off"].includes(s)) return false;
    return v;
  }, z.boolean().default(defaultValue));
}

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
  // Required for Catalyst v1 signing domain separation.
  GENESIS_HASH: z.string().min(1),

  // Default to 8080 so the web UI can run on Next.js' default 3000 locally.
  PORT: z.coerce.number().int().positive().default(8080),
  HOST: z.string().default("0.0.0.0"),
  GLOBAL_RPM: z.coerce.number().int().positive().default(60),
  ENABLE_COUNTRY_LIMIT: envBool(false),
  ENABLE_ASN_LIMIT: envBool(false),
});

export type AppConfig = Readonly<{
  rpcUrl: string;
  chainId: number;
  faucetPrivateKeyHex: string;
  faucetAmount: string;
  faucetAmountUnits: bigint;
  cooldownHours: number;
  cooldownMs: number;
  redisUrl: string;
  databaseUrl: string;
  turnstileSecretKey: string;
  adminToken: string;
  ipHashSalt: string;
  genesisHash: string;
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

  let faucetAmountUnits: bigint;
  try {
    // Catalyst transfers use integer units (protocol atom). For public testnet faucet,
    // configure whole-unit amounts (e.g. "1000").
    faucetAmountUnits = BigInt(parsed.FAUCET_AMOUNT);
  } catch {
    throw new Error(`Invalid FAUCET_AMOUNT (expected integer units): ${parsed.FAUCET_AMOUNT}`);
  }
  if (faucetAmountUnits <= 0n) {
    throw new Error(`Invalid FAUCET_AMOUNT (must be > 0): ${parsed.FAUCET_AMOUNT}`);
  }

  const cooldownMs = parsed.COOLDOWN_HOURS * 60 * 60 * 1000;

  const explorerBaseUrl = "https://explorer.catalystnet.org";
  const explorerTxTemplate = `${explorerBaseUrl}/tx/<txHash>`;

  const genesisHash = parsed.GENESIS_HASH.trim().toLowerCase();
  if (!isHex32(genesisHash)) {
    throw new Error(`Invalid GENESIS_HASH (expected 0x + 64 hex chars): ${parsed.GENESIS_HASH}`);
  }

  const faucetPrivateKeyHex = parsed.FAUCET_PRIVATE_KEY.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(faucetPrivateKeyHex)) {
    throw new Error("Invalid FAUCET_PRIVATE_KEY (expected 32-byte hex)");
  }

  return {
    rpcUrl: parsed.RPC_URL,
    chainId,
    faucetPrivateKeyHex,
    faucetAmount: parsed.FAUCET_AMOUNT,
    faucetAmountUnits,
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

