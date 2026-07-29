import { env } from "cloudflare:workers";
import { desc, eq } from "drizzle-orm";
import { getDb } from "../../../db";
import {
  getVaultSession,
  hashMasterPassword,
} from "../../../db/auth";
import { ensureVaultSchema } from "../../../db/ensure";
import {
  decryptSmtpSecret,
  encryptSmtpSecret,
  getStoredSmtpConfig,
  normalizeSmtpHost,
  normalizeSmtpProvider,
  normalizeSmtpSecurity,
  validateSmtpPort,
  validateSmtpUsername,
} from "../../../db/smtp-config";
import { sendSmtpMail } from "../../../db/smtp";
import {
  securitySettings,
  trustedDevices,
  vaultEntries,
} from "../../../db/schema";

export const dynamic = "force-dynamic";

const ENCRYPTED_RECORD_PREFIX = "yv2.";
const encryptedStorageFields = {
  projectName: "加密记录",
  account: "••••••••",
  category: "已加密",
  notes: "",
};

function isNotificationEmailConfigured(email: string) {
  return (
    !email.includes("*") &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  );
}

function errorResponse(error: unknown) {
  const message = error instanceof Error ? error.message : "Unexpected error";
  return Response.json({ error: message }, { status: 500 });
}

async function authorize(request: Request) {
  const session = await getVaultSession(request);
  if (!session) {
    return {
      session: null,
      response: Response.json(
        { error: "本次访问尚未通过服务端校验" },
        { status: 401 },
      ),
    };
  }
  return { session, response: null };
}

export async function GET(request: Request) {
  try {
    await ensureVaultSchema();
    const authorization = await authorize(request);
    if (authorization.response) return authorization.response;

    const db = getDb();
    const [entries, devices, settingsRows] = await Promise.all([
      db
        .select({
          id: vaultEntries.id,
          projectName: vaultEntries.projectName,
          account: vaultEntries.account,
          category: vaultEntries.category,
          securityStatus: vaultEntries.securityStatus,
          passwordCipher: vaultEntries.passwordCipher,
          passwordIv: vaultEntries.passwordIv,
          notes: vaultEntries.notes,
          updatedAt: vaultEntries.updatedAt,
        })
        .from(vaultEntries)
        .orderBy(desc(vaultEntries.updatedAt)),
      db
        .select()
        .from(trustedDevices)
        .orderBy(desc(trustedDevices.lastActive)),
      db
        .select()
        .from(securitySettings)
        .where(eq(securitySettings.id, 1))
        .limit(1),
    ]);

    const settings = settingsRows[0];
    return Response.json({
      entries,
      devices,
      settings: settings
        ? {
            twoFactorEnabled: settings.twoFactorEnabled,
            email: settings.email,
            maxFailedAttempts: settings.maxFailedAttempts,
            lockoutMinutes: settings.lockoutMinutes,
            smtpProvider: settings.smtpProvider,
            smtpHost: settings.smtpHost,
            smtpPort: settings.smtpPort,
            smtpSecurity: settings.smtpSecurity,
            smtpUsername: settings.smtpUsername,
            smtpFromName: settings.smtpFromName,
            smtpEnabled: settings.smtpEnabled,
            smtpFeatureEnabled: settings.smtpFeatureEnabled,
            smtpVerifiedAt: settings.smtpVerifiedAt,
            hasSmtpSecret: Boolean(
              settings.smtpSecretCipher && settings.smtpSecretIv,
            ),
          }
        : {
            twoFactorEnabled: true,
            email: "w***@example.com",
            maxFailedAttempts: 5,
            lockoutMinutes: 15,
            smtpProvider: "",
            smtpHost: "",
            smtpPort: 465,
            smtpSecurity: "tls",
            smtpUsername: "",
            smtpFromName: "钥密",
            smtpEnabled: false,
            smtpFeatureEnabled: false,
            smtpVerifiedAt: null,
            hasSmtpSecret: false,
          },
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: Request) {
  try {
    await ensureVaultSchema();
    const authorization = await authorize(request);
    if (authorization.response || !authorization.session) {
      return authorization.response;
    }

    const payload = (await request.json()) as Record<string, unknown>;
    const action = String(payload.action ?? "");
    const db = getDb();

    if (action === "change-master-password") {
      const currentPassword = String(payload.currentPassword ?? "");
      const newPassword = String(payload.newPassword ?? "");
      const entries = Array.isArray(payload.entries) ? payload.entries : [];
      const passwordGroups = [
        /[a-z]/.test(newPassword),
        /[A-Z]/.test(newPassword),
        /\d/.test(newPassword),
        /[^A-Za-z0-9]/.test(newPassword),
      ].filter(Boolean).length;

      if (!currentPassword) {
        return Response.json(
          { error: "请输入当前主密码" },
          { status: 400 },
        );
      }
      if (
        newPassword.length < 10 ||
        newPassword.length > 128 ||
        passwordGroups < 3
      ) {
        return Response.json(
          { error: "新主密码需为 10–128 位，并至少包含三类字符" },
          { status: 400 },
        );
      }
      if (currentPassword === newPassword) {
        return Response.json(
          { error: "新主密码不能与当前主密码相同" },
          { status: 400 },
        );
      }

      const settings = await db
        .select({ masterPasswordHash: securitySettings.masterPasswordHash })
        .from(securitySettings)
        .where(eq(securitySettings.id, 1))
        .limit(1);
      const currentHash = await hashMasterPassword(currentPassword);
      if (
        !settings[0]?.masterPasswordHash ||
        currentHash !== settings[0].masterPasswordHash
      ) {
        return Response.json(
          { error: "当前主密码不正确" },
          { status: 403 },
        );
      }

      const storedEntries = await db
        .select({
          id: vaultEntries.id,
          passwordCipher: vaultEntries.passwordCipher,
          passwordIv: vaultEntries.passwordIv,
        })
        .from(vaultEntries);
      const recordsToRotate = storedEntries.filter(
        (entry) =>
          entry.passwordCipher !== "encrypted-demo-value" &&
          entry.passwordIv !== "demo-iv",
      );
      if (recordsToRotate.length > 2000) {
        return Response.json(
          { error: "单次最多可更新 2000 条密码记录" },
          { status: 400 },
        );
      }
      if (entries.length !== recordsToRotate.length) {
        return Response.json(
          { error: "密码库内容已变化，请刷新页面后重试" },
          { status: 409 },
        );
      }

      const storedIds = new Set(recordsToRotate.map((entry) => entry.id));
      const nextEntries: Array<{
        id: string;
        passwordCipher: string;
        passwordIv: string;
      }> = [];
      const receivedIds = new Set<string>();
      for (const entry of entries) {
        const record = entry as Record<string, unknown>;
        const id = String(record.id ?? "");
        const passwordCipher = String(record.passwordCipher ?? "");
        const passwordIv = String(record.passwordIv ?? "");
        if (
          !storedIds.has(id) ||
          receivedIds.has(id) ||
          passwordCipher.length > 200_000 ||
          passwordIv.length > 256 ||
          !/^yv2\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/.test(passwordCipher) ||
          !/^[A-Za-z0-9+/=]+$/.test(passwordIv)
        ) {
          return Response.json(
            { error: "主密码更新包含无效的加密记录" },
            { status: 400 },
          );
        }
        receivedIds.add(id);
        nextEntries.push({ id, passwordCipher, passwordIv });
      }

      const newHash = await hashMasterPassword(newPassword);
      const updatedAt = new Date()
        .toISOString()
        .slice(0, 16)
        .replace("T", " ");
      await env.DB.batch([
        ...nextEntries.map((entry) =>
          env.DB.prepare(
            `UPDATE vault_entries
             SET project_name = ?, account = ?, category = ?, notes = ?,
                 password_cipher = ?, password_iv = ?, updated_at = ?
             WHERE id = ?`,
          ).bind(
            encryptedStorageFields.projectName,
            encryptedStorageFields.account,
            encryptedStorageFields.category,
            encryptedStorageFields.notes,
            entry.passwordCipher,
            entry.passwordIv,
            updatedAt,
            entry.id,
          ),
        ),
        env.DB.prepare(
          "UPDATE security_settings SET master_password_hash = ? WHERE id = 1",
        ).bind(newHash),
        env.DB.prepare("DELETE FROM vault_sessions"),
        env.DB.prepare("DELETE FROM login_attempts"),
        env.DB.prepare("DELETE FROM verification_challenges"),
      ]);

      return Response.json({
        ok: true,
        rotated: nextEntries.length,
        sessionsRevoked: true,
      });
    }

    if (action === "import-entries") {
      const entries = Array.isArray(payload.entries) ? payload.entries : [];
      if (!entries.length || entries.length > 2000) {
        return Response.json(
          { error: "单次需要导入 1–2000 条加密记录" },
          { status: 400 },
        );
      }

      const encryptedEntries: Array<{
        passwordCipher: string;
        passwordIv: string;
      }> = [];
      for (const entry of entries) {
        const record = entry as Record<string, unknown>;
        const passwordCipher = String(record.passwordCipher ?? "");
        const passwordIv = String(record.passwordIv ?? "");
        if (
          passwordCipher.length > 200_000 ||
          passwordIv.length > 256 ||
          !/^yv2\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/.test(passwordCipher) ||
          !/^[A-Za-z0-9+/=]+$/.test(passwordIv)
        ) {
          return Response.json(
            { error: "导入文件包含无效的加密密码记录" },
            { status: 400 },
          );
        }
        encryptedEntries.push({ passwordCipher, passwordIv });
      }

      const updatedAt = new Date()
        .toISOString()
        .slice(0, 16)
        .replace("T", " ");
      for (let offset = 0; offset < encryptedEntries.length; offset += 50) {
        const chunk = encryptedEntries.slice(offset, offset + 50);
        await env.DB.batch(
          chunk.map((entry) =>
            env.DB.prepare(
              `INSERT INTO vault_entries
                (id, project_name, account, category, security_status, password_cipher, password_iv, notes, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            ).bind(
              crypto.randomUUID(),
              encryptedStorageFields.projectName,
              encryptedStorageFields.account,
              encryptedStorageFields.category,
              "安全",
              entry.passwordCipher,
              entry.passwordIv,
              encryptedStorageFields.notes,
              updatedAt,
            ),
          ),
        );
      }
      return Response.json(
        { ok: true, imported: encryptedEntries.length },
        { status: 201 },
      );
    }

    if (action === "add-entry") {
      const projectName = String(payload.projectName ?? "").trim();
      const account = String(payload.account ?? "").trim();
      const category = String(payload.category ?? "").trim();
      const passwordCipher = String(payload.passwordCipher ?? "");
      const passwordIv = String(payload.passwordIv ?? "");
      const notes = String(payload.notes ?? "").trim();

      if (
        !projectName ||
        !account ||
        !category ||
        !passwordCipher ||
        !passwordIv
      ) {
        return Response.json({ error: "缺少密码记录字段" }, { status: 400 });
      }

      await db.insert(vaultEntries).values({
        id: crypto.randomUUID(),
        ...(passwordCipher.startsWith(ENCRYPTED_RECORD_PREFIX)
          ? encryptedStorageFields
          : { projectName, account, category, notes }),
        passwordCipher,
        passwordIv,
        securityStatus: "安全",
        updatedAt: new Date().toISOString().slice(0, 16).replace("T", " "),
      });
      return Response.json({ ok: true }, { status: 201 });
    }

    if (action === "update-entry") {
      const id = String(payload.id ?? "").trim();
      const projectName = String(payload.projectName ?? "").trim();
      const account = String(payload.account ?? "").trim();
      const category = String(payload.category ?? "").trim();
      const passwordCipher = String(payload.passwordCipher ?? "");
      const passwordIv = String(payload.passwordIv ?? "");
      const notes = String(payload.notes ?? "").trim();

      if (!id || !projectName || !account || !category) {
        return Response.json({ error: "缺少密码记录字段" }, { status: 400 });
      }
      if (
        (passwordCipher && !passwordIv) ||
        (!passwordCipher && passwordIv)
      ) {
        return Response.json({ error: "新密码密文不完整" }, { status: 400 });
      }

      await db
        .update(vaultEntries)
        .set({
          ...(passwordCipher.startsWith(ENCRYPTED_RECORD_PREFIX)
            ? encryptedStorageFields
            : { projectName, account, category, notes }),
          updatedAt: new Date().toISOString().slice(0, 16).replace("T", " "),
          ...(passwordCipher && passwordIv
            ? { passwordCipher, passwordIv, securityStatus: "安全" }
            : {}),
        })
        .where(eq(vaultEntries.id, id));
      return Response.json({ ok: true });
    }

    if (action === "set-two-factor") {
      const enabled = Boolean(payload.enabled);
      if (enabled) {
        const settings = await db
          .select({
            email: securitySettings.email,
            smtpEnabled: securitySettings.smtpEnabled,
            smtpFeatureEnabled: securitySettings.smtpFeatureEnabled,
            smtpSecretCipher: securitySettings.smtpSecretCipher,
            smtpSecretIv: securitySettings.smtpSecretIv,
          })
          .from(securitySettings)
          .where(eq(securitySettings.id, 1))
          .limit(1);
        if (!isNotificationEmailConfigured(settings[0]?.email ?? "")) {
          return Response.json(
            { error: "请先保存有效的通知邮箱" },
            { status: 400 },
          );
        }
        if (
          !settings[0]?.smtpEnabled ||
          !settings[0]?.smtpFeatureEnabled ||
          !settings[0]?.smtpSecretCipher ||
          !settings[0]?.smtpSecretIv
        ) {
          return Response.json(
            { error: "请先保存 SMTP 配置并发送测试邮件" },
            { status: 400 },
          );
        }
      }
      await db
        .update(securitySettings)
        .set({ twoFactorEnabled: enabled })
        .where(eq(securitySettings.id, 1));
      return Response.json({ ok: true });
    }

    if (action === "set-smtp-feature") {
      const enabled = Boolean(payload.enabled);
      await db
        .update(securitySettings)
        .set({
          smtpFeatureEnabled: enabled,
          ...(enabled ? {} : { twoFactorEnabled: false }),
        })
        .where(eq(securitySettings.id, 1));
      return Response.json({ ok: true, enabled });
    }

    if (action === "set-smtp-config") {
      const provider = normalizeSmtpProvider(payload.provider);
      const host = normalizeSmtpHost(payload.host);
      const port = validateSmtpPort(payload.port);
      const security = normalizeSmtpSecurity(payload.security);
      const username = String(payload.username ?? "").trim().toLowerCase();
      const secret = String(payload.secret ?? "").trim();
      const fromName =
        String(payload.fromName ?? "钥密")
          .replace(/[\r\n]+/g, " ")
          .trim()
          .slice(0, 40) || "钥密";

      if (!provider) {
        return Response.json(
          { error: "请填写邮箱服务商名称" },
          { status: 400 },
        );
      }
      if (!host) {
        return Response.json(
          { error: "请输入有效的公网 SMTP 服务器域名" },
          { status: 400 },
        );
      }
      if (!port) {
        return Response.json(
          { error: "SMTP 端口必须为 1–65535，且不能使用端口 25" },
          { status: 400 },
        );
      }
      if (!security) {
        return Response.json(
          { error: "请选择 SSL/TLS 或 STARTTLS" },
          { status: 400 },
        );
      }
      const usernameError = validateSmtpUsername(username);
      if (usernameError) {
        return Response.json({ error: usernameError }, { status: 400 });
      }

      const feature = await db
        .select({ enabled: securitySettings.smtpFeatureEnabled })
        .from(securitySettings)
        .where(eq(securitySettings.id, 1))
        .limit(1);
      if (!feature[0]?.enabled) {
        return Response.json(
          { error: "请先开启 SMTP 邮件服务" },
          { status: 400 },
        );
      }

      const current = await getStoredSmtpConfig();
      if (
        !secret &&
        (!current?.secretCipher ||
          current.provider !== provider ||
          current.host !== host ||
          current.port !== port ||
          current.security !== security ||
          current.username !== username)
      ) {
        return Response.json(
          { error: "请输入 SMTP 授权码或应用专用密码" },
          { status: 400 },
        );
      }
      if (secret && (secret.length < 6 || secret.length > 160)) {
        return Response.json(
          { error: "SMTP 授权码或应用专用密码长度不正确" },
          { status: 400 },
        );
      }

      const encrypted = secret ? await encryptSmtpSecret(secret) : null;
      await db
        .update(securitySettings)
        .set({
          smtpProvider: provider,
          smtpHost: host,
          smtpPort: port,
          smtpSecurity: security,
          smtpUsername: username,
          smtpFromName: fromName,
          smtpEnabled: false,
          smtpVerifiedAt: null,
          twoFactorEnabled: false,
          ...(encrypted
            ? {
                smtpSecretCipher: encrypted.cipher,
                smtpSecretIv: encrypted.iv,
              }
            : {}),
        })
        .where(eq(securitySettings.id, 1));

      return Response.json({
        ok: true,
        provider,
        host,
        port,
        security,
      });
    }

    if (action === "test-smtp") {
      const settings = await db
        .select({ email: securitySettings.email })
        .from(securitySettings)
        .where(eq(securitySettings.id, 1))
        .limit(1);
      const notificationEmail = settings[0]?.email ?? "";
      if (!isNotificationEmailConfigured(notificationEmail)) {
        return Response.json(
          { error: "请先保存接收测试邮件的通知邮箱" },
          { status: 400 },
        );
      }

      const smtp = await getStoredSmtpConfig();
      if (
        !smtp ||
        !smtp.featureEnabled ||
        !smtp.secretCipher ||
        !smtp.secretIv
      ) {
        return Response.json(
          { error: "请先保存完整的 SMTP 配置" },
          { status: 400 },
        );
      }
      const secret = await decryptSmtpSecret(
        smtp.secretCipher,
        smtp.secretIv,
      );
      await sendSmtpMail({
        host: smtp.host,
        port: smtp.port,
        username: smtp.username,
        secret,
        security: smtp.security,
        fromName: smtp.fromName,
        to: notificationEmail,
        subject: "钥密 SMTP 测试成功",
        text: [
          "这是一封来自钥密密码管理器的测试邮件。",
          "",
          `服务商：${smtp.provider}`,
          `服务器：${smtp.host}:${smtp.port}（${
            smtp.security === "tls" ? "SSL/TLS" : "STARTTLS"
          }）`,
          `发件账号：${smtp.username}`,
          "",
          "收到此邮件表示新设备验证码和主密码找回邮件可以正常发送。",
        ].join("\n"),
      });

      const verifiedAt = new Date().toISOString();
      await db
        .update(securitySettings)
        .set({ smtpEnabled: true, smtpVerifiedAt: verifiedAt })
        .where(eq(securitySettings.id, 1));
      return Response.json({ ok: true, verifiedAt });
    }

    if (action === "set-recovery-email") {
      const email = String(payload.email ?? "").trim().toLowerCase();
      if (email && !isNotificationEmailConfigured(email)) {
        return Response.json(
          { error: "通知邮箱格式不正确" },
          { status: 400 },
        );
      }

      await db
        .update(securitySettings)
        .set({
          email,
          ...(email ? {} : { twoFactorEnabled: false }),
        })
        .where(eq(securitySettings.id, 1));
      return Response.json({ ok: true });
    }

    if (action === "set-lockout-policy") {
      const maxFailedAttempts = Number(payload.maxFailedAttempts);
      const lockoutMinutes = Number(payload.lockoutMinutes);
      if (
        !Number.isInteger(maxFailedAttempts) ||
        maxFailedAttempts < 2 ||
        maxFailedAttempts > 10 ||
        !Number.isInteger(lockoutMinutes) ||
        lockoutMinutes < 1 ||
        lockoutMinutes > 1440
      ) {
        return Response.json({ error: "锁定策略参数无效" }, { status: 400 });
      }

      await db
        .update(securitySettings)
        .set({ maxFailedAttempts, lockoutMinutes })
        .where(eq(securitySettings.id, 1));
      return Response.json({ ok: true });
    }

    if (action === "delete-device") {
      const id = String(payload.id ?? "");
      if (!id) {
        return Response.json({ error: "设备 ID 不能为空" }, { status: 400 });
      }

      await env.DB.batch([
        env.DB.prepare("DELETE FROM trusted_devices WHERE id = ?").bind(id),
        env.DB.prepare("DELETE FROM vault_sessions WHERE device_id = ?").bind(
          id,
        ),
        env.DB.prepare("DELETE FROM login_attempts WHERE device_id = ?").bind(
          id,
        ),
      ]);
      return Response.json({
        ok: true,
        removedCurrentDevice: id === authorization.session.deviceId,
      });
    }

    return Response.json({ error: "未知操作" }, { status: 400 });
  } catch (error) {
    return errorResponse(error);
  }
}
