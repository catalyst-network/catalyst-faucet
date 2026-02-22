import { apiError } from "../errors";

type TurnstileVerifyParams = {
  token: string;
  ip?: string;
  idempotencyKey?: string;
};

type TurnstileResponse = {
  success: boolean;
  "error-codes"?: string[];
  challenge_ts?: string;
  hostname?: string;
  action?: string;
  cdata?: string;
};

export function createTurnstileVerifier(secretKey: string) {
  return async function verifyTurnstile(params: TurnstileVerifyParams): Promise<void> {
    const form = new URLSearchParams();
    form.set("secret", secretKey);
    form.set("response", params.token);
    if (params.ip) form.set("remoteip", params.ip);

    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        ...(params.idempotencyKey ? { "x-idempotency-key": params.idempotencyKey } : {}),
      },
      body: form,
    });

    if (!res.ok) {
      throw apiError({
        statusCode: 503,
        code: "UPSTREAM_UNAVAILABLE",
        message: "Faucet is temporarily unavailable",
        details: { hint: "try again later" },
      });
    }

    const data = (await res.json()) as TurnstileResponse;
    if (!data.success) {
      throw apiError({
        statusCode: 403,
        code: "TURNSTILE_FAILED",
        message: "Verification failed",
        details: data["error-codes"]?.length ? { errorCodes: data["error-codes"] } : undefined,
      });
    }
  };
}

