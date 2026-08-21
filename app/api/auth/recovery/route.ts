import { env } from "@/runtime/database";
import {
  createAccessChallenge,
  createCodeChallenge,
  consumeAccessChallenge,
  consumeCodeChallenge,
} from "../../../../db/challenges";
import { ensureVaultSchema } from "../../../../db/ensure";
import {
  clientAddress,
  enforceRateLimit,
  readJsonBody,
  requestErrorResponse,
} from "../../../../db/http-security";
import { getStoredSmtpConfig, getReadySmtpConfig } from "../../../../db/smtp-config";
import { sendSmtpMail } from "../../../../db/smtp";

export const dynamic = "force-dynamic";

const RECOVERY_CHALLENGE_DEVICE = "password-recovery";

function isNotificationEmailConfigured(email: string) {
  return !email.includes("*") && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function maskEmail(email: string) {
  const [local, domain] = email.split("@");
  const visible = local.slice(0, Math.min(2, local.length));
  return `${visible}${"•".repeat(Math.max(3, local.length - visible.length))}@${domain}`;
}

type RecoverySettings = {
  email: string;
  requiresPasswordChange: number;
  recoveryCipher: string;
  recoveryIv: string;
  recoverySalt: string;
  recoveryIterations: number;
};

async function getRecoveryStatus() {
  const settings = await env.DB.prepare(
    `SELECT email,
      requires_password_change AS requiresPasswordChange,
      recovery_cipher AS recoveryCipher,
      recovery_iv AS recoveryIv,
      recovery_salt AS recoverySalt,
      recovery_iterations AS recoveryIterations
     FROM security_settings WHERE id = 1`,
  ).first<RecoverySettings>();
  const smtp = await getStoredSmtpConfig();
  const email = settings?.email?.trim() ?? "";
  const emailReady =
    isNotificationEmailConfigured(email) &&
    Boolean(smtp?.featureEnabled && smtp.enabled && smtp.secretCipher && smtp.secretIv);
  const recoveryKeyConfigured = Boolean(
    settings?.recoveryCipher && settings.recoveryIv && settings.recoverySalt,
  );
  return {
    email,
    emailReady,
    recoveryKeyConfigured,
    configured: emailReady && recoveryKeyConfigured,
    requiresPasswordChange: Boolean(settings?.requiresPasswordChange),
    material: settings
      ? {
          cipher: settings.recoveryCipher,
          iv: settings.recoveryIv,
          salt: settings.recoverySalt,
          iterations: settings.recoveryIterations,
        }
      : null,
  };
}

export async function GET() {
  try {
    await ensureVaultSchema();
    const status = await getRecoveryStatus();
    return Response.json(
      {
        configured: status.configured,
        emailReady: status.emailReady,
        recoveryKeyConfigured: status.recoveryKeyConfigured,
        maskedEmail: status.configured ? maskEmail(status.email) : "",
        requiresPasswordChange: status.requiresPasswordChange,
      },
      { headers: { "cache-control": "no-store" } },
    );
  } catch {
    return Response.json(
      {
        configured: false,
        emailReady: false,
        recoveryKeyConfigured: false,
        maskedEmail: "",
        requiresPasswordChange: false,
      },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }
}

export async function POST(request: Request) {
  try {
    const address = clientAddress(request);
    const rate = enforceRateLimit(`recovery:${address}`, 8, 15 * 60_000);
    if (!rate.allowed) {
      return Response.json(
        { error: "找回请求过于频繁，请稍后再试" },
        { status: 429, headers: { "retry-after": String(rate.retryAfter) } },
      );
    }
    await ensureVaultSchema();
    const payload = await readJsonBody(request);
    const action = String(payload.action ?? "");
    const status = await getRecoveryStatus();
    if (!status.configured || !status.material) {
      return Response.json(
        { error: "请先在设置中完成通知邮箱、SMTP 和恢复密钥配置" },
        { status: 409 },
      );
    }

    if (action === "request-code") {
      const mailRate = enforceRateLimit(`recovery-mail:${address}`, 3, 15 * 60_000);
      if (!mailRate.allowed) {
        return Response.json(
          { error: "验证码发送次数过多，请稍后再试" },
          { status: 429, headers: { "retry-after": String(mailRate.retryAfter) } },
        );
      }
      const challenge = await createCodeChallenge(
        RECOVERY_CHALLENGE_DEVICE,
        "recovery-code",
      );
      try {
        const smtp = await getReadySmtpConfig();
        await sendSmtpMail({
          host: smtp.host,
          port: smtp.port,
          username: smtp.username,
          secret: smtp.secret,
          security: smtp.security,
          fromName: smtp.fromName,
          to: status.email,
          subject: "钥密主密码恢复验证码",
          text: [
            "你正在申请恢复钥密密码管理器的主密码。",
            "",
            `一次性验证码：${challenge.code}`,
            "",
            "验证码 10 分钟内有效，且只能使用一次。钥密不会通过邮件发送或重置你的主密码。",
          ].join("\n"),
        });
      } catch (error) {
        await env.DB.prepare(
          "DELETE FROM verification_challenges WHERE token_hash = ?",
        )
          .bind(challenge.tokenHash)
          .run();
        throw error;
      }
      return Response.json({
        sent: true,
        challengeToken: challenge.token,
        maskedEmail: maskEmail(status.email),
      });
    }

    if (action === "verify-code") {
      const code = String(payload.code ?? "").trim();
      const challengeToken = String(payload.challengeToken ?? "").trim();
      if (!/^\d{6}$/.test(code) || !/^[A-Za-z0-9_-]{32,128}$/.test(challengeToken)) {
        return Response.json({ error: "验证码格式不正确" }, { status: 400 });
      }
      const result = await consumeCodeChallenge({
        token: challengeToken,
        code,
        purpose: "recovery-code",
        deviceId: RECOVERY_CHALLENGE_DEVICE,
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
                ? "验证码已过期，请重新发送"
                : `验证码不正确${attempts}`,
          },
          { status: 401 },
        );
      }
      const recoveryToken = await createAccessChallenge(
        RECOVERY_CHALLENGE_DEVICE,
        "recovery-access",
      );
      return Response.json({
        recoveryToken,
        maskedEmail: maskEmail(status.email),
      });
    }

    if (action === "get-material") {
      const recoveryToken = String(payload.recoveryToken ?? "").trim();
      const email = String(payload.email ?? "").trim().toLowerCase();
      if (
        !/^[A-Za-z0-9_-]{32,128}$/.test(recoveryToken) ||
        email.length > 254 ||
        email !== status.email.toLowerCase()
      ) {
        return Response.json({ error: "找回凭证不正确" }, { status: 401 });
      }
      const consumed = await consumeAccessChallenge(
        recoveryToken,
        "recovery-access",
      );
      if (!consumed) {
        return Response.json(
          { error: "找回验证已过期，请重新完成邮箱验证" },
          { status: 401 },
        );
      }
      return Response.json({
        material: status.material,
        maskedEmail: maskEmail(status.email),
      });
    }

    return Response.json({ error: "未知找回操作" }, { status: 400 });
  } catch (error) {
    const requestError = requestErrorResponse(error);
    if (requestError) return requestError;
    const message = error instanceof Error ? error.message : "主密码找回失败";
    return Response.json({ error: message }, { status: 500 });
  }
}
