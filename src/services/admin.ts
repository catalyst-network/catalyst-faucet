import type { FastifyRequest } from "fastify";

function extractAdminToken(req: FastifyRequest): string | undefined {
  const h = req.headers;
  const direct = (h["x-admin-token"] as string | undefined)?.trim();
  if (direct) return direct;

  const auth = (h["authorization"] as string | undefined)?.trim();
  if (!auth) return undefined;
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  return m?.[1]?.trim();
}

export function createAdminAuth(adminToken: string) {
  return {
    assertAdmin(req: FastifyRequest) {
      const token = extractAdminToken(req);
      if (!token || token !== adminToken) {
        const err = new Error("Unauthorized");
        (err as any).statusCode = 401;
        throw err;
      }
    },
  };
}

