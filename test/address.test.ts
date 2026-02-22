import { describe, expect, test } from "vitest";
import { ethers } from "ethers";
import { createFaucetSender } from "../src/services/faucet";

describe("address validation", () => {
  test("normalizeAddress accepts valid EVM address and returns checksummed", () => {
    const faucet = createFaucetSender({
      // not used by normalizeAddress in tests
      provider: {} as any,
      wallet: {} as any,
      amountWei: 1n,
    });

    const normalized = faucet.normalizeAddress("0x000000000000000000000000000000000000dead");
    expect(normalized).toEqual(ethers.getAddress("0x000000000000000000000000000000000000dEaD"));
  });

  test("normalizeAddress rejects invalid address", () => {
    const faucet = createFaucetSender({ provider: {} as any, wallet: {} as any, amountWei: 1n });
    expect(() => faucet.normalizeAddress("not-an-address")).toThrowError();
    try {
      faucet.normalizeAddress("not-an-address");
    } catch (e: any) {
      expect(e.statusCode).toBe(400);
    }
  });
});

