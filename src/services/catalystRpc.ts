type JsonRpcRequest = {
  jsonrpc: "2.0";
  id: number;
  method: string;
  params: unknown[];
};

type JsonRpcError = {
  code: number;
  message: string;
  data?: unknown;
};

type JsonRpcResponse<T> =
  | { jsonrpc: "2.0"; id: number; result: T }
  | { jsonrpc: "2.0"; id: number; error: JsonRpcError };

export type CatalystRpcTransactionRequest = {
  from: string;
  to?: string | null;
  value?: string | null;
  data?: string | null;
  gas_limit?: number | null;
  gas_price?: string | null;
};

export function createCatalystRpcClient(rpcUrl: string) {
  let nextId = 1;

  async function call<T>(method: string, params: unknown[]): Promise<T> {
    const body: JsonRpcRequest = { jsonrpc: "2.0", id: nextId++, method, params };
    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      throw new Error(`RPC returned non-JSON (${res.status}): ${text.slice(0, 200)}`);
    }
    if (!res.ok) {
      throw new Error(`RPC HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    const msg = parsed as JsonRpcResponse<T>;
    if ("error" in msg) {
      throw new Error(`RPC error ${msg.error.code}: ${msg.error.message}`);
    }
    return msg.result;
  }

  return {
    chainId: () => call<string>("catalyst_chainId", []),
    genesisHash: () => call<string>("catalyst_genesisHash", []),
    networkId: () => call<string>("catalyst_networkId", []),
    getSyncInfo: () => call<{ chain_id: string; network_id: string; genesis_hash: string }>("catalyst_getSyncInfo", []),
    blockNumber: () => call<number>("catalyst_blockNumber", []),
    getNonce: (address: string) => call<number>("catalyst_getNonce", [address]),
    estimateFee: (req: CatalystRpcTransactionRequest) => call<string>("catalyst_estimateFee", [req]),
    sendRawTransaction: (wireHex: string) => call<string>("catalyst_sendRawTransaction", [wireHex]),
    getTransactionReceipt: (txId: string) => call<unknown>("catalyst_getTransactionReceipt", [txId]),
  };
}

