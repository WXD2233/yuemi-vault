import { env } from "@/runtime/database";
import {
  createVaultSession,
  hashSecret,
  verifyMasterPassword,
} from "../../../../db/auth";
import { createCodeChallenge } from "../../../../db/challenges";
import {
  hasTrustedDeviceCredential,
  registerTrustedDevice,
  touchTrustedDevice,
} from "../../../../db/devices";
import { ensureVaultSchema } from "../../../../db/ensure";
import {
  clientAddress,
  enforceRateLimit,
  readJsonBody,
  requestErrorResponse,
} from "../../../../db/http-security";
import {
  DEFAULT_MASTER_PASSWORD,
  LEGACY_DEFAULT_MASTER_PASSWORD_HASH,
} from "../../../../db/security-constants";
import { getReadySmtpConfig } from "../../../../db/smtp-config";
import { sendSmtpMail } from "../../../../db/smtp";

export const dynamic = "force-dynamic";

type SecurityRow = {
  twoFactorEnabled: number;
  email: string;
  masterPasswordHash: string;
  masterPasswordSalt: string;
  masterPasswordIterations: number;
  maxFailedAttempts: number;
  lockoutMinutes: number;
  smtpEnabled: number;
  smtpFeatureEnabled: number;
};

function isNotificationEmailConfigured(email: string) {
  return !email.includes("*") && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function bounded(value: unknown, fallback: string, max: number) {
  return String(value ?? fallback).trim().slice(0, max) || fallback;
}

export async function POST(request: Request) {
  try {
    const address = clientAddress(request);
    const rate = enforceRateLimit(`unlock:${address}`, 15, 60_000);
    if (!rate.allowed) {
      return Response.json(
        { error: "登录请求过于频繁，请稍后再试" },
        { status: 429, headers: { "retry-after": String(rate.retryAfter) } },
      );
    }

    await ensureVaultSchema();
    const payload = await readJsonBody(request);
    const deviceId = String(payload.deviceId ?? "").trim();
    const deviceCredential = String(payload.deviceCredential ?? "").trim();
    const masterPassword = String(payload.masterPassword ?? "");
    const deviceName = bounded(payload.deviceName, "桌面设备", 120);
    const browser = bounded(payload.browser, "浏览器", 120);
    const location = bounded(payload.location, "当前网络", 120);

    if (
      !/^[A-Za-z0-9_-]{8,128}$/.test(deviceId) ||
      !masterPassword ||
      masterPassword.length > 128 ||
      deviceCredential.length > 128
    ) {
      return Response.json(
        { error: "登录信息格式不正确" },
        { status: 400 },
      );
    }

    const settings = await env.DB.prepare(
      `SELECT two_factor_enabled AS twoFactorEnabled, email,
        master_password_hash AS masterPasswordHash,
        master_password_salt AS masterPasswordSalt,
        master_password_iterations AS masterPasswordIterations,
        max_failed_attempts AS maxFailedAttempts,
        lockout_minutes AS lockoutMinutes,
        smtp_enabled AS smtpEnabled,
        smtp_feature_enabled AS smtpFeatureEnabled
       FROM security_settings WHERE id = 1`,
    ).first<SecurityRow>();
    if (!settings) {
      return Response.json({ error: "安全设置不可用" }, { status: 500 });
    }

    const addressHash = await hashSecret(address);
    const attemptKey = `ip:${addressHash.slice(0, 40)}`;
    const attempt = await env.DB.prepare(
      "SELECT failed_count AS failedCount, locked_until AS lockedUntil FROM login_attempts WHERE device_id = ?",
    )
      .bind(attemptKey)
      .first<{ failedCount: number; lockedUntil: string | null }>();
    const lockedUntilMs = attempt?.lockedUntil ? Date.parse(attempt.lockedUntil) : 0;
    if (lockedUntilMs > Date.now()) {
      return Response.json(
        {
          error: "当前网络因多次输入错误已被临时锁定",
          lockedUntil: attempt?.lockedUntil,
          remainingSeconds: Math.ceil((lockedUntilMs - Date.now()) / 1000),
        },
        { status: 423 },
      );
    }

    const validPassword = await verifyMasterPassword(
      masterPassword,
      settings.masterPasswordHash,
      settings.masterPasswordSalt,
      settings.masterPasswordIterations,
    );
    const acceptedLegacyDefault =
      settings.masterPasswordHash === LEGACY_DEFAULT_MASTER_PASSWORD_HASH &&
      masterPassword === DEFAULT_MASTER_PASSWORD;

    if (!validPassword && !acceptedLegacyDefault) {
      await env.DB.prepare(
        "DELETE FROM login_attempts WHERE updated_at < datetime('now', '-7 days')",
      ).run();
      const now = new Date().toISOString();
      const lockedUntil = new Date(
        Date.now() + settings.lockoutMinutes * 60_000,
      ).toISOString();
      const updated = await env.DB.prepare(
        `INSERT INTO login_attempts
          (device_id, failed_count, locked_until, updated_at)
         VALUES (?, 1, NULL, CURRENT_TIMESTAMP)
         ON CONFLICT(device_id) DO UPDATE SET
           failed_count = CASE
             WHEN login_attempts.locked_until IS NOT NULL
                  AND login_attempts.locked_until <= ? THEN 1
             ELSE login_attempts.failed_count + 1
           END,
           locked_until = CASE
             WHEN (CASE
               WHEN login_attempts.locked_until IS NOT NULL
                    AND login_attempts.locked_until <= ? THEN 1
               ELSE login_attempts.failed_count + 1
             END) >= ? THEN ?
             ELSE NULL
           END,
           updated_at = CURRENT_TIMESTAMP
         RETURNING failed_count AS failedCount, locked_until AS lockedUntil`,
      )
        .bind(attemptKey, now, now, settings.maxFailedAttempts, lockedUntil)
        .first<{ failedCount: number; lockedUntil: string | null }>();
      const failedCount = updated?.failedCount ?? 1;
      if (updated?.lockedUntil) {
        return Response.json(
          {
            error: `密码连续错误 ${settings.maxFailedAttempts} 次，当前网络已锁定 ${settings.lockoutMinutes} 分钟`,
            lockedUntil: updated.lockedUntil,
            remainingSeconds: settings.lockoutMinutes * 60,
          },
          { status: 423 },
        );
      }
      return Response.json(
        {
          error: "主密码不正确",
          attemptsRemaining: Math.max(0, settings.maxFailedAttempts - failedCount),
        },
        { status: 401 },
      );
    }

    await env.DB.prepare("DELETE FROM login_attempts WHERE device_id = ?")
      .bind(attemptKey)
      .run();
    await env.DB.prepare(
      "DELETE FROM login_attempts WHERE updated_at < datetime('now', '-7 days')",
    ).run();

    const trusted = await hasTrustedDeviceCredential(deviceId, deviceCredential);
    if (
      settings.twoFactorEnabled &&
      settings.smtpFeatureEnabled &&
      isNotificationEmailConfigured(settings.email) &&
      !trusted
    ) {
      if (!settings.smtpEnabled) {
        return Response.json(
          { error: "新设备验证邮件尚未配置，请先在已验证设备中测试 SMTP" },
          { status: 503 },
        );
      }

      const challenge = await createCodeChallenge(deviceId, "device");
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
            `验证码：${challenge.code}`,
            "",
            "验证码只能使用一次，10 分钟内有效。若非本人操作，请立即修改主密码。",
          ].join("\n"),
        });
      } catch (error) {
        await env.DB.prepare(
          "DELETE FROM verification_challenges WHERE token_hash = ?",
        )
          .bind(challenge.tokenHash)
          .run();
        const detail = error instanceof Error ? error.message : "SMTP 发送失败";
        return Response.json(
          { error: `验证码邮件发送失败：${detail}` },
          { status: 502 },
        );
      }
      return Response.json({
        needsVerification: true,
        challengeToken: challenge.token,
        email: settings.email,
        emailSent: true,
      });
    }

    let nextDeviceCredential: string | undefined;
    if (trusted) {
      await touchTrustedDevice(deviceId);
    } else {
      nextDeviceCredential = await registerTrustedDevice({
        deviceId,
        deviceName,
        browser,
        location,
      });
    }
    const sessionToken = await createVaultSession(deviceId);
    return Response.json({
      needsVerification: false,
      sessionToken,
      ...(nextDeviceCredential
        ? { deviceCredential: nextDeviceCredential }
        : {}),
    });
  } catch (error) {
    const requestError = requestErrorResponse(error);
    if (requestError) return requestError;
    const message = error instanceof Error ? error.message : "验证失败";
    return Response.json({ error: message }, { status: 500 });
  }
}
