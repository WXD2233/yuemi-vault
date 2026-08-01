import { env } from "@/runtime/database";
import {
  createOpaqueToken,
  createVaultSession,
  hashMasterPassword,
  hashSecret,
} from "../../../../db/auth";
import { ensureVaultSchema } from "../../../../db/ensure";
import { getReadySmtpConfig } from "../../../../db/smtp-config";
import { sendSmtpMail } from "../../../../db/smtp";
import {
  DEFAULT_MASTER_PASSWORD,
  LEGACY_DEFAULT_MASTER_PASSWORD_HASH,
} from "../../../../db/security-constants";

export const dynamic = "force-dynamic";

type SecurityRow = {
  twoFactorEnabled: number;
  email: string;
  masterPasswordHash: string;
  maxFailedAttempts: number;
  lockoutMinutes: number;
  smtpEnabled: number;
  smtpFeatureEnabled: number;
};

const FIXED_VERIFICATION_CODE = "246810";

function isNotificationEmailConfigured(email: string) {
  return (
    !email.includes("*") &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  );
}

export async function POST(request: Request) {
  try {
    await ensureVaultSchema();
    const payload = (await request.json()) as Record<string, unknown>;
    const deviceId = String(payload.deviceId ?? "").trim();
    const masterPassword = String(payload.masterPassword ?? "");
    const deviceName = String(payload.deviceName ?? "Windows 桌面设备");
    const browser = String(payload.browser ?? "浏览器");
    const location = String(payload.location ?? "当前网络");

    if (!deviceId || !masterPassword) {
      return Response.json(
        { error: "请输入主密码并提供设备标识" },
        { status: 400 },
      );
    }

    const settings = await env.DB.prepare(
      `SELECT
        two_factor_enabled AS twoFactorEnabled,
        email,
        master_password_hash AS masterPasswordHash,
        max_failed_attempts AS maxFailedAttempts,
        lockout_minutes AS lockoutMinutes,
        smtp_enabled AS smtpEnabled,
        smtp_feature_enabled AS smtpFeatureEnabled
      FROM security_settings
      WHERE id = 1`,
    ).first<SecurityRow>();

    if (!settings) {
      return Response.json({ error: "安全设置不可用" }, { status: 500 });
    }

    const attempt = await env.DB.prepare(
      "SELECT failed_count AS failedCount, locked_until AS lockedUntil FROM login_attempts WHERE device_id = ?",
    )
      .bind(deviceId)
      .first<{ failedCount: number; lockedUntil: string | null }>();

    const lockedUntilMs = attempt?.lockedUntil
      ? Date.parse(attempt.lockedUntil)
      : 0;
    if (lockedUntilMs > Date.now()) {
      return Response.json(
        {
          error: "该设备因多次输入错误已被临时锁定",
          lockedUntil: attempt?.lockedUntil,
          remainingSeconds: Math.ceil((lockedUntilMs - Date.now()) / 1000),
        },
        { status: 423 },
      );
    }

    const providedHash = await hashMasterPassword(masterPassword);
    const acceptedLegacyDefault =
      settings.masterPasswordHash ===
        LEGACY_DEFAULT_MASTER_PASSWORD_HASH &&
      masterPassword === DEFAULT_MASTER_PASSWORD;
    if (
      providedHash !== settings.masterPasswordHash &&
      !acceptedLegacyDefault
    ) {
      const failedCount = (attempt?.failedCount ?? 0) + 1;
      const shouldLock = failedCount >= settings.maxFailedAttempts;
      const lockedUntil = shouldLock
        ? new Date(Date.now() + settings.lockoutMinutes * 60_000).toISOString()
        : null;

      await env.DB.prepare(
        `INSERT INTO login_attempts (device_id, failed_count, locked_until, updated_at)
         VALUES (?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(device_id) DO UPDATE SET
           failed_count = excluded.failed_count,
           locked_until = excluded.locked_until,
           updated_at = CURRENT_TIMESTAMP`,
      )
        .bind(deviceId, failedCount, lockedUntil)
        .run();

      if (shouldLock) {
        return Response.json(
          {
            error: `密码连续错误 ${settings.maxFailedAttempts} 次，该设备已锁定 ${settings.lockoutMinutes} 分钟`,
            lockedUntil,
            remainingSeconds: settings.lockoutMinutes * 60,
          },
          { status: 423 },
        );
      }

      return Response.json(
        {
          error: "主密码不正确",
          attemptsRemaining: settings.maxFailedAttempts - failedCount,
        },
        { status: 401 },
      );
    }

    await env.DB.prepare(
      `INSERT INTO login_attempts (device_id, failed_count, locked_until, updated_at)
       VALUES (?, 0, NULL, CURRENT_TIMESTAMP)
       ON CONFLICT(device_id) DO UPDATE SET
         failed_count = 0,
         locked_until = NULL,
         updated_at = CURRENT_TIMESTAMP`,
    )
      .bind(deviceId)
      .run();

    const trustedDevice = await env.DB.prepare(
      "SELECT id FROM trusted_devices WHERE id = ?",
    )
      .bind(deviceId)
      .first<{ id: string }>();

    if (
      settings.twoFactorEnabled &&
      settings.smtpFeatureEnabled &&
      isNotificationEmailConfigured(settings.email) &&
      !trustedDevice
    ) {
      if (!settings.smtpEnabled) {
        return Response.json(
          { error: "新设备验证邮件尚未配置，请先在旧设备的设置中测试 SMTP" },
          { status: 503 },
        );
      }

      const challengeToken = createOpaqueToken();
      const challengeHash = await hashSecret(challengeToken);
      const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
      await env.DB.prepare(
        "INSERT INTO verification_challenges (token_hash, device_id, expires_at) VALUES (?, ?, ?)",
      )
        .bind(challengeHash, deviceId, expiresAt)
        .run();

      try {
        const smtp = await getReadySmtpConfig();
        await sendSmtpMail({
          host: smtp.host,
          port: smtp.port,
          username: smtp.username,
          secret: smtp.secret,
          security: smtp.security,
          fromName: smtp.fromName,
          to: settings.email,
          subject: "钥密新设备验证码",
          text: [
            "检测到一台新设备正在尝试进入你的钥密密码库。",
            "",
            `验证码：${FIXED_VERIFICATION_CODE}`,
            "",
            "验证码 10 分钟内有效。如果不是你本人操作，请不要向任何人提供此验证码。",
          ].join("\n"),
        });
      } catch (error) {
        await env.DB.prepare(
          "DELETE FROM verification_challenges WHERE token_hash = ?",
        )
          .bind(challengeHash)
          .run();
        const detail =
          error instanceof Error ? error.message : "SMTP 发送失败";
        return Response.json(
          { error: `验证码邮件发送失败：${detail}` },
          { status: 502 },
        );
      }

      return Response.json({
        needsVerification: true,
        challengeToken,
        email: settings.email,
        emailSent: true,
      });
    }

    if (trustedDevice) {
      await env.DB.prepare(
        "UPDATE trusted_devices SET last_active = ? WHERE id = ?",
      )
        .bind("刚刚", deviceId)
        .run();
    } else {
      await env.DB.prepare(
        `INSERT INTO trusted_devices (id, device_name, browser, location, last_active, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          deviceId,
          deviceName,
          browser,
          location,
          "刚刚",
          new Date().toISOString().slice(0, 10),
        )
        .run();
    }

    const sessionToken = await createVaultSession(deviceId);
    return Response.json({ needsVerification: false, sessionToken });
  } catch (error) {
    const message = error instanceof Error ? error.message : "验证失败";
    return Response.json({ error: message }, { status: 500 });
  }
}
