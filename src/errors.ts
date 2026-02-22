export type ApiErrorCode =
  | "INVALID_REQUEST"
  | "INVALID_ADDRESS"
  | "TURNSTILE_FAILED"
  | "COOLDOWN_ACTIVE"
  | "UPSTREAM_UNAVAILABLE"
  | "UNAUTHORIZED"
  | "INTERNAL_ERROR";

export class ApiError extends Error {
  readonly statusCode: number;
  readonly code: ApiErrorCode;
  readonly details?: unknown;
  readonly meta?: Record<string, unknown>;

  constructor(params: {
    statusCode: number;
    code: ApiErrorCode;
    message: string;
    details?: unknown;
    meta?: Record<string, unknown>;
  }) {
    super(params.message);
    this.statusCode = params.statusCode;
    this.code = params.code;
    this.details = params.details;
    this.meta = params.meta;
  }
}

export function apiError(params: ConstructorParameters<typeof ApiError>[0]): ApiError {
  return new ApiError(params);
}

