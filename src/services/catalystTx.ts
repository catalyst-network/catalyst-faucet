import { randomBytes } from "crypto";

type Noble = {
  blake2b: typeof import("@noble/hashes/blake2.js").blake2b;
  ristretto255: typeof import("@noble/curves/ed25519.js").ristretto255;
  mod: typeof import("@noble/curves/abstract/modular.js").mod;
};

let noblePromise: Promise<Noble> | null = null;
async function noble(): Promise<Noble> {
  if (!noblePromise) {
    noblePromise = Promise.all([
      import("@noble/hashes/blake2.js"),
      import("@noble/curves/ed25519.js"),
      import("@noble/curves/abstract/modular.js"),
    ]).then(([h, c, m]) => ({
      blake2b: h.blake2b,
      ristretto255: c.ristretto255,
      mod: m.mod,
    }));
  }
  return noblePromise;
}

const TX_WIRE_MAGIC_V1 = new TextEncoder().encode("CTX1");
const TX_SIG_DOMAIN_V1 = new TextEncoder().encode("CATALYST_SIG_V1");

export type CatalystAddress = `0x${string}`;

export function normalizeCatalystAddress(input: string): CatalystAddress {
  const v = input.trim().toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(v)) {
    throw new Error("Invalid address (expected 0x + 32-byte hex pubkey)");
  }
  return v as CatalystAddress;
}

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error("Invalid hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToNumberLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) + BigInt(bytes[i]!);
  }
  return n;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function blake2b256(data: Uint8Array): Uint8Array {
  // Only used from async code paths that loaded noble.
  throw new Error("blake2b256 called before noble loaded");
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u8(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff);
}
function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}
function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  dv.setBigUint64(0, n, true);
  return b;
}
function i64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  dv.setBigInt64(0, n, true);
  return b;
}

// --- Canonical serialization (CatalystSerialize) ---

type TxType = 0; // NonConfidentialTransfer

type EntryAmount = { kind: "nonconfidential"; value: bigint };

type TxEntry = { publicKey32: Uint8Array; amount: EntryAmount };

type TxCore = {
  txType: TxType;
  entries: TxEntry[];
  nonce: bigint;
  lockTime: number;
  fees: bigint;
  data: Uint8Array;
};

type Tx = {
  core: TxCore;
  signature: Uint8Array; // 64 bytes (wrapped as Vec<u8> in encoding)
  timestamp: bigint;
};

function serializeVec(items: Uint8Array[]): Uint8Array {
  return concatBytes([u32le(items.length), ...items]);
}

function serializeBytesVec(bytes: Uint8Array): Uint8Array {
  return concatBytes([u32le(bytes.length), bytes]);
}

function serializeEntryAmount(a: EntryAmount): Uint8Array {
  if (a.kind !== "nonconfidential") throw new Error("Unsupported amount kind");
  // tag 0 + i64 le
  return concatBytes([u8(0), i64le(a.value)]);
}

function serializeTxEntry(e: TxEntry): Uint8Array {
  if (e.publicKey32.length !== 32) throw new Error("publicKey32 must be 32 bytes");
  return concatBytes([e.publicKey32, serializeEntryAmount(e.amount)]);
}

function serializeTxType(t: TxType): Uint8Array {
  return u8(t);
}

function serializeTxCore(c: TxCore): Uint8Array {
  const entryBytes = c.entries.map(serializeTxEntry);
  return concatBytes([
    serializeTxType(c.txType),
    serializeVec(entryBytes),
    u64le(c.nonce),
    u32le(c.lockTime),
    u64le(c.fees),
    serializeBytesVec(c.data),
  ]);
}

function serializeTx(tx: Tx): Uint8Array {
  if (tx.signature.length !== 64) throw new Error("Signature must be 64 bytes");
  return concatBytes([
    serializeTxCore(tx.core),
    serializeBytesVec(tx.signature),
    u64le(tx.timestamp),
  ]);
}

export async function derivePubkey32FromPrivateKeyHex(
  privateKeyHex: string,
): Promise<Uint8Array> {
  const { ristretto255, mod } = await noble();
  const pk = privateKeyHex.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(pk)) throw new Error("Invalid private key hex");
  const privBytes = hexToBytes(pk);
  const x = mod(bytesToNumberLE(privBytes), ristretto255.Point.Fn.ORDER);
  return ristretto255.Point.BASE.multiply(x).toBytes();
}

async function schnorrSign(
  privKeyHex: string,
  message: Uint8Array,
): Promise<Uint8Array> {
  const { ristretto255, mod, blake2b } = await noble();
  const pk = privKeyHex.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(pk)) throw new Error("Invalid private key hex");
  const xBytes = hexToBytes(pk);
  const x = mod(bytesToNumberLE(xBytes), ristretto255.Point.Fn.ORDER);
  const P = ristretto255.Point.BASE.multiply(x).toBytes();

  const kBytes = randomBytes(32);
  const k = mod(bytesToNumberLE(kBytes), ristretto255.Point.Fn.ORDER);
  const R = ristretto255.Point.BASE.multiply(k).toBytes();

  const eBytes = blake2b(concatBytes([R, P, message]), { dkLen: 64 }).slice(0, 32);
  const e = mod(bytesToNumberLE(eBytes), ristretto255.Point.Fn.ORDER);

  const s = mod(k + e * x, ristretto255.Point.Fn.ORDER);
  const sBytes = ristretto255.Point.Fn.toBytes(ristretto255.Point.Fn.create(s));

  const sig = new Uint8Array(64);
  sig.set(R, 0);
  sig.set(sBytes, 32);
  return sig;
}

export async function buildSignedTransferTxV1(params: {
  faucetPrivateKeyHex: string;
  faucetPubkey32: Uint8Array;
  to: CatalystAddress;
  amount: bigint;
  nonce: bigint;
  fees: bigint;
  chainId: bigint;
  genesisHashHex: string; // 0x + 32 bytes
  nowMs: number;
}): Promise<{ wireHex: string; txIdHex: string }> {
  const { blake2b } = await noble();
  const toAddr = normalizeCatalystAddress(params.to);
  const toPk = hexToBytes(toAddr);
  const faucetPk = params.faucetPubkey32;
  if (faucetPk.length !== 32) throw new Error("Invalid faucet pubkey32");
  if (toPk.length !== 32) throw new Error("Invalid recipient pubkey32");

  const amountI64 = BigInt(params.amount);
  if (amountI64 <= 0n) throw new Error("Amount must be > 0");
  const I64_MAX = (1n << 63n) - 1n;
  if (amountI64 > I64_MAX) throw new Error("Amount too large for i64");
  if (params.fees < 0n) throw new Error("Fees must be >= 0");
  const U64_MAX = (1n << 64n) - 1n;
  if (params.fees > U64_MAX) throw new Error("Fees too large for u64");

  const lockTime = Math.floor(params.nowMs / 1000);
  if (lockTime < 0 || lockTime > 0xffffffff) throw new Error("lockTime out of range");

  const core: TxCore = {
    txType: 0,
    entries: [
      { publicKey32: faucetPk, amount: { kind: "nonconfidential", value: -amountI64 } },
      { publicKey32: toPk, amount: { kind: "nonconfidential", value: amountI64 } },
    ],
    nonce: params.nonce,
    lockTime,
    fees: params.fees,
    data: new Uint8Array(),
  };

  const timestamp = BigInt(params.nowMs);
  const genesisHash = params.genesisHashHex.trim().toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(genesisHash)) throw new Error("Invalid genesis hash hex");
  const genesisHashBytes = hexToBytes(genesisHash);

  const signingPayload = concatBytes([
    TX_SIG_DOMAIN_V1,
    u64le(params.chainId),
    genesisHashBytes,
    serializeTxCore(core),
    u64le(timestamp),
  ]);

  const signature = await schnorrSign(params.faucetPrivateKeyHex, signingPayload);

  const tx: Tx = { core, signature, timestamp };
  const body = serializeTx(tx);
  const wire = concatBytes([TX_WIRE_MAGIC_V1, body]);

  // tx_id = blake2b512(wire)[..32]
  const txId = blake2b(wire, { dkLen: 64 }).slice(0, 32);

  return {
    wireHex: `0x${bytesToHex(wire)}`,
    txIdHex: `0x${bytesToHex(txId)}`,
  };
}

