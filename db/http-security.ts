import { isIP } from "node:net";

export class RequestBodyError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export async function readJsonBody(
  request: Request,
  maxBytes = 16 * 1024,
): Promise<Record<string, unknown>> {
  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new RequestBodyError("请求内容过大", 413);
  }
  if (!request.body) return {};

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new RequestBodyError("请求内容过大", 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("not an object");
    }
    return value as Record<string, unknown>;
  } catch {
    throw new RequestBodyError("请求格式不正确");
  }
}

export function clientAddress(request: Request) {
  const forwardedValues = request.headers.get("x-forwarded-for")?.split(",");
  const forwarded = forwardedValues?.[forwardedValues.length - 1];
  const candidate = (
    forwarded || request.headers.get("x-real-ip") || "unknown"
  ).trim();
  return isIP(candidate) ? candidate : "unknown";
}

type RateState = { count: number; resetAt: number };
const rateStates = new Map<string, RateState>();

export function enforceRateLimit(
  key: string,
  limit: number,
  windowMs: number,
) {
  const now = Date.now();
  if (rateStates.size > 10_000) {
    for (const [stateKey, state] of rateStates) {
      if (state.resetAt <= now) rateStates.delete(stateKey);
    }
    while (rateStates.size > 10_000) {
      const oldestKey = rateStates.keys().next().value as string | undefined;
      if (!oldestKey) break;
      rateStates.delete(oldestKey);
    }
  }
  const current = rateStates.get(key);
  if (!current || current.resetAt <= now) {
    rateStates.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfter: 0 };
  }
  current.count += 1;
  if (current.count > limit) {
    return {
      allowed: false,
      retryAfter: Math.max(1, Math.ceil((current.resetAt - now) / 1000)),
    };
  }
  return { allowed: true, retryAfter: 0 };
}

export function requestErrorResponse(error: unknown) {
  if (error instanceof RequestBodyError) {
    return Response.json(
      { error: error.message },
      { status: error.status, headers: { "cache-control": "no-store" } },
    );
  }
  return null;
}
