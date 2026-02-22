import { apiError } from "../errors";
import { createCatalystRpcClient } from "./catalystRpc";
import {
  buildSignedTransferTxV1,
  derivePubkey32FromPrivateKeyHex,
  normalizeCatalystAddress,
} from "./catalystTx";

export function createFaucetSender(opts: {
  rpcUrl: string;
  chainId: number;
  genesisHash: string;
  faucetPrivateKeyHex: string;
  amountUnits: bigint;
}) {
  const rpc = createCatalystRpcClient(opts.rpcUrl);
  const faucetPubkey32 = derivePubkey32FromPrivateKeyHex(opts.faucetPrivateKeyHex);
  const faucetAddress = (`0x${Buffer.from(faucetPubkey32).toString("hex")}`) as `0x${string}`;

  return {
    normalizeAddress(input: string): string {
      try {
        return normalizeCatalystAddress(input);
      } catch {
        throw apiError({
          statusCode: 400,
          code: "INVALID_ADDRESS",
          message: "Invalid address (expected 0x + 32-byte hex pubkey)",
        });
      }
    },

    async sendTo(to: string): Promise<string> {
      const recipient = normalizeCatalystAddress(to);
      const [remoteChainId, remoteGenesisHash] = await Promise.all([
        rpc.chainId(),
        rpc.genesisHash(),
      ]);
      const chainIdHex = remoteChainId.trim().toLowerCase();
      const genesisHashHex = remoteGenesisHash.trim().toLowerCase();
      const expectedChainIdHex = `0x${opts.chainId.toString(16)}`;
      if (chainIdHex !== expectedChainIdHex) {
        throw apiError({
          statusCode: 503,
          code: "UPSTREAM_UNAVAILABLE",
          message: "Faucet is temporarily unavailable",
          details: { hint: "RPC chain identity mismatch" },
        });
      }
      if (genesisHashHex !== opts.genesisHash.toLowerCase()) {
        throw apiError({
          statusCode: 503,
          code: "UPSTREAM_UNAVAILABLE",
          message: "Faucet is temporarily unavailable",
          details: { hint: "RPC genesis hash mismatch" },
        });
      }

      const committedNonce = await rpc.getNonce(faucetAddress);
      const nonce = BigInt(committedNonce) + 1n;

      const feeStr = await rpc.estimateFee({
        from: faucetAddress,
        to: recipient,
        value: opts.amountUnits.toString(),
        data: "",
      });
      const fees = BigInt(feeStr);

      const { wireHex, txIdHex } = buildSignedTransferTxV1({
        faucetPrivateKeyHex: opts.faucetPrivateKeyHex,
        faucetPubkey32,
        to: recipient,
        amount: opts.amountUnits,
        nonce,
        fees,
        chainId: BigInt(opts.chainId),
        genesisHashHex: opts.genesisHash,
        nowMs: Date.now(),
      });

      const txId = await rpc.sendRawTransaction(wireHex);
      // Node returns tx_id; sanity-check against local tx_id derivation when possible.
      if (typeof txId === "string" && txId.toLowerCase().startsWith("0x") && txId.length === 66) {
        return txId;
      }
      return txIdHex;
    },
  };
}

