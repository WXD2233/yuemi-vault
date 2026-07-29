import { env } from "cloudflare:workers";
import {
  createOpaqueToken,
  hashMasterPassword,
  hashSecret,
} from "../../../../db/auth";
import { ensureVaultSchema } from "../../../../db/ensure";
import {
  getReadySmtpConfig,
  getStoredSmtpConfig,
} from "../../../../db/smtp-config";
import { sendSmtpMail } from "../../../../db/smtp";
import {
  DEFAULT_MASTER_PASSWORD,
  DEFAULT_MASTER_PASSWORD_HASH,
  LEGACY_DEFAULT_MASTER_PASSWORD_HASH,
} from "../../../../db/security-constants";

export const dynamic = "force-dynamic";

const DEMO_CODE = "246810";
const RECOVERY_CHALLENGE_DEVICE = "password-recovery";

function isNotificationEmailConfigured(email: string) {
  return (
    !email.includes("*") &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  );
}

function maskEmail(email: string) {
  const [local, domain] = email.split("@");
  const visible = local.slice(0, Math.min(2, local.length));
  return `${visible}${"•".repeat(Math.max(3, local.length - visible.length))}@${domain}`;
}

async function getLoginSettings() {
  const settings = await env.DB.prepare(
    `SELECT
      email,
      master_password_hash AS masterPasswordHash
     FROM security_settings
     WHERE id = 1`,
  ).first<{ email: string; masterPasswordHash: string }>();
  return {
    email: settings?.email?.trim() ?? "",
    requiresPasswordChange:
      settings?.masterPasswordHash === DEFAULT_MASTER_PASSWORD_HASH ||
      settings?.masterPasswordHash === LEGACY_DEFAULT_MASTER_PASSWORD_HASH,
  };
}

async function getRecoveryStatus() {
  const loginSettings = await getLoginSettings();
  const smtp = await getStoredSmtpConfig();
  const configured =
    isNotificationEmailConfigured(loginSettings.email) &&
    Boolean(
      smtp?.featureEnabled &&
        smtp.enabled &&
        smtp.secretCipher &&
        smtp.secretIv,
    );
  return { ...loginSettings, configured };
}

export async function GET() {
  try {
    await ensureVaultSchema();
    const { email, configured, requiresPasswordChange } =
      await getRecoveryStatus();
    return Response.json({
      configured,
      maskedEmail: configured ? maskEmail(email) : "",
      requiresPasswordChange,
    });
  } catch {
    return Response.json(
      {
        configured: false,
        maskedEmail: "",
        requiresPasswordChange: false,
      },
      { status: 503 },
    );
  }
}

export async function POST(request: Request) {
  try {
    await ensureVaultSchema();
    const payload = (await request.json()) as Record<string, unknown>;
    const action = String(payload.action ?? "");
    const { email: configuredEmail, configured } = await getRecoveryStatus();

    if (!configured) {
      return Response.json(
        { error: "请先在设置中保存通知邮箱并测试 SMTP 邮件服务" },
        { status: 409 },
      );
    }

    if (action === "request-code") {
      const smtp = await getReadySmtpConfig();
      await sendSmtpMail({
        host: smtp.host,
        port: smtp.port,
        username: smtp.username,
        secret: smtp.secret,
        security: smtp.security,
        fromName: smtp.fromName,
        to: configuredEmail,
        subject: "钥密主密码找回验证码",
        text: [
          "你正在申请找回钥密密码管理器的主密码。",
          "",
          `两步验证码：${DEMO_CODE}`,
          "",
          "验证码 10 分钟内有效。如果不是你本人操作，请忽略此邮件。",
        ].join("\n"),
      });
      return Response.json({
        sent: true,
        maskedEmail: maskEmail(configuredEmail),
      });
    }

    if (action === "verify-code") {
      const code = String(payload.code ?? "").trim();
      if (code !== DEMO_CODE) {
        return Response.json(
          { error: "两步验证码不正确" },
          { status: 401 },
        );
      }

      const recoveryToken = createOpaqueToken();
      const tokenHash = await hashSecret(recoveryToken);
      const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();

      await env.DB.batch([
        env.DB.prepare(
          "DELETE FROM verification_challenges WHERE device_id = ? OR expires_at <= ?",
        ).bind(RECOVERY_CHALLENGE_DEVICE, new Date().toISOString()),
        env.DB.prepare(
          "INSERT INTO verification_challenges (token_hash, device_id, expires_at) VALUES (?, ?, ?)",
        ).bind(tokenHash, RECOVERY_CHALLENGE_DEVICE, expiresAt),
      ]);

      return Response.json({
        recoveryToken,
        maskedEmail: maskEmail(configuredEmail),
      });
    }

    if (action === "send-password") {
      const recoveryToken = String(payload.recoveryToken ?? "").trim();
      const email = String(payload.email ?? "").trim().toLowerCase();
      if (!recoveryToken || !email) {
        return Response.json(
          { error: "请输入设置中保存的通知邮箱" },
          { status: 400 },
        );
      }

      const tokenHash = await hashSecret(recoveryToken);
      const challenge = await env.DB.prepare(
        "SELECT device_id AS deviceId, expires_at AS expiresAt FROM verification_challenges WHERE token_hash = ?",
      )
        .bind(tokenHash)
        .first<{ deviceId: string; expiresAt: string }>();

      if (
        !challenge ||
        challenge.deviceId !== RECOVERY_CHALLENGE_DEVICE ||
        Date.parse(challenge.expiresAt) <= Date.now()
      ) {
        return Response.json(
          { error: "找回验证已过期，请重新完成两步验证" },
          { status: 401 },
        );
      }

      if (email !== configuredEmail.toLowerCase()) {
        return Response.json(
          { error: "通知邮箱与设置中保存的邮箱不一致" },
          { status: 401 },
        );
      }

      const smtp = await getReadySmtpConfig();
      await sendSmtpMail({
        host: smtp.host,
        port: smtp.port,
        username: smtp.username,
        secret: smtp.secret,
        security: smtp.security,
        fromName: smtp.fromName,
        to: configuredEmail,
        subject: "钥密新的主密码",
        text: [
          "你的钥密默认主密码已重新设置。",
          "",
          `新主密码：${DEFAULT_MASTER_PASSWORD}`,
          "",
          "请使用默认主密码登录，并立即设置新的主密码。为安全起见，请勿转发此邮件。",
        ].join("\n"),
      });

      const demoPasswordHash = await hashMasterPassword(
        DEFAULT_MASTER_PASSWORD,
      );
      await env.DB.batch([
        env.DB.prepare(
          "UPDATE security_settings SET master_password_hash = ? WHERE id = 1",
        ).bind(demoPasswordHash),
        env.DB.prepare(
          "DELETE FROM verification_challenges WHERE token_hash = ?",
        ).bind(tokenHash),
        env.DB.prepare("DELETE FROM vault_sessions"),
        env.DB.prepare("DELETE FROM login_attempts"),
      ]);

      return Response.json({
        delivered: true,
        maskedEmail: maskEmail(configuredEmail),
      });
    }

    return Response.json({ error: "未知找回操作" }, { status: 400 });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "主密码找回失败";
    return Response.json({ error: message }, { status: 500 });
  }
}
