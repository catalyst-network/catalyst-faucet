import { ethers } from "ethers";

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
        const err = new Error("Invalid address");
        (err as any).statusCode = 400;
        throw err;
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

