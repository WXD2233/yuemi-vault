import { createVaultSession } from "../../../../db/auth";
import { consumeCodeChallenge } from "../../../../db/challenges";
import { registerTrustedDevice } from "../../../../db/devices";
import { ensureVaultSchema } from "../../../../db/ensure";
import {
  clientAddress,
  enforceRateLimit,
  readJsonBody,
  requestErrorResponse,
} from "../../../../db/http-security";

export const dynamic = "force-dynamic";

function bounded(value: unknown, fallback: string, max: number) {
  return String(value ?? fallback).trim().slice(0, max) || fallback;
}

export async function POST(request: Request) {
  try {
    const address = clientAddress(request);
    const rate = enforceRateLimit(`verify:${address}`, 12, 10 * 60_000);
    if (!rate.allowed) {
      return Response.json(
        { error: "验证码尝试过于频繁，请稍后再试" },
        { status: 429, headers: { "retry-after": String(rate.retryAfter) } },
      );
    }
    await ensureVaultSchema();
    const payload = await readJsonBody(request);
    const code = String(payload.code ?? "").trim();
    const challengeToken = String(payload.challengeToken ?? "").trim();
    const deviceId = String(payload.deviceId ?? "").trim();
    const deviceName = bounded(payload.deviceName, "桌面设备", 120);
    const browser = bounded(payload.browser, "浏览器", 120);
    const location = bounded(payload.location, "当前网络", 120);

    if (
      !/^\d{6}$/.test(code) ||
      !/^[A-Za-z0-9_-]{32,128}$/.test(challengeToken) ||
      !/^[A-Za-z0-9_-]{8,128}$/.test(deviceId)
    ) {
      return Response.json({ error: "验证码请求格式不正确" }, { status: 400 });
    }

    const result = await consumeCodeChallenge({
      token: challengeToken,
      code,
      purpose: "device",
      deviceId,
    });
    if (!result.ok) {
      const attempts =
        result.reason === "invalid" && result.attemptsRemaining
          ? `，还可尝试 ${result.attemptsRemaining} 次`
          : "";
      return Response.json(
        {
          error:
            result.reason === "expired"
              ? "验证码已过期，请重新输入主密码"
              : `邮箱验证码不正确${attempts}`,
        },
        { status: 401 },
      );
    }

    const deviceCredential = await registerTrustedDevice({
      deviceId,
      deviceName,
      browser,
      location,
    });
    const sessionToken = await createVaultSession(deviceId);
    return Response.json({ sessionToken, deviceCredential });
  } catch (error) {
    const requestError = requestErrorResponse(error);
    if (requestError) return requestError;
    const message = error instanceof Error ? error.message : "设备验证失败";
    return Response.json({ error: message }, { status: 500 });
  }
}
