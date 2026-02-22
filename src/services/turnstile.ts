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
      const err = new Error(`Turnstile verify failed (http ${res.status})`);
      (err as any).statusCode = 502;
      throw err;
    }

    const data = (await res.json()) as TurnstileResponse;
    if (!data.success) {
      const err = new Error(
        `Invalid captcha${data["error-codes"]?.length ? `: ${data["error-codes"].join(",")}` : ""}`,
      );
      (err as any).statusCode = 400;
      throw err;
    }
  };
}

