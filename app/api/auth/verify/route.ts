import { env } from "cloudflare:workers";
import { createVaultSession, hashSecret } from "../../../../db/auth";
import { ensureVaultSchema } from "../../../../db/ensure";

export const dynamic = "force-dynamic";

const DEMO_CODE = "246810";

export async function POST(request: Request) {
  try {
    await ensureVaultSchema();
    const payload = (await request.json()) as Record<string, unknown>;
    const code = String(payload.code ?? "");
    const challengeToken = String(payload.challengeToken ?? "");
    const deviceId = String(payload.deviceId ?? "");
    const deviceName = String(payload.deviceName ?? "Windows 桌面设备");
    const browser = String(payload.browser ?? "浏览器");
    const location = String(payload.location ?? "当前网络");

    if (!challengeToken || !deviceId) {
      return Response.json({ error: "验证请求已失效" }, { status: 400 });
    }

    const challengeHash = await hashSecret(challengeToken);
    const challenge = await env.DB.prepare(
      "SELECT device_id AS deviceId, expires_at AS expiresAt FROM verification_challenges WHERE token_hash = ?",
    )
      .bind(challengeHash)
      .first<{ deviceId: string; expiresAt: string }>();

    if (
      !challenge ||
      challenge.deviceId !== deviceId ||
      Date.parse(challenge.expiresAt) <= Date.now()
    ) {
      return Response.json(
        { error: "验证码会话已过期，请重新输入主密码" },
        { status: 401 },
      );
    }

    if (code !== DEMO_CODE) {
      return Response.json({ error: "邮箱验证码不正确" }, { status: 401 });
    }

    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO trusted_devices (id, device_name, browser, location, last_active, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           device_name = excluded.device_name,
           browser = excluded.browser,
           location = excluded.location,
           last_active = excluded.last_active`,
      ).bind(
        deviceId,
        deviceName,
        browser,
        location,
        "刚刚",
        new Date().toISOString().slice(0, 10),
      ),
      env.DB.prepare(
        "DELETE FROM verification_challenges WHERE token_hash = ?",
      ).bind(challengeHash),
    ]);

    const sessionToken = await createVaultSession(deviceId);
    return Response.json({ sessionToken });
  } catch (error) {
    const message = error instanceof Error ? error.message : "设备验证失败";
    return Response.json({ error: message }, { status: 500 });
  }
}
