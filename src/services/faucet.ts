import { ethers } from "ethers";
import { apiError } from "../errors";

export function createFaucetSender(opts: {
  provider: ethers.JsonRpcProvider;
  wallet: ethers.Wallet;
  amountWei: bigint;
}) {
  return {
    normalizeAddress(input: string): string {
      try {
        return ethers.getAddress(input);
      } catch {
        throw apiError({
          statusCode: 400,
          code: "INVALID_ADDRESS",
          message: "Invalid address",
        });
      }
    },

    async sendTo(to: string): Promise<string> {
      const tx = await opts.wallet.sendTransaction({
        to,
        value: opts.amountWei,
      });
      return tx.hash;
    },
  };
}

