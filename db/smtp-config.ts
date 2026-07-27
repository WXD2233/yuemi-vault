import { env } from "cloudflare:workers";

export type SmtpProvider = "qq" | "163" | "gmail";

export const SMTP_PRESETS: Record<
  SmtpProvider,
  { label: string; host: string; port: number; credentialLabel: string }
> = {
  qq: {
    label: "QQ 邮箱",
    host: "smtp.qq.com",
    port: 465,
    credentialLabel: "SMTP 授权码",
  },
  "163": {
    label: "163 邮箱",
    host: "smtp.163.com",
    port: 465,
    credentialLabel: "客户端授权密码",
  },
  gmail: {
    label: "Gmail",
    host: "smtp.gmail.com",
    port: 465,
    credentialLabel: "应用专用密码",
  },
};

type StoredSmtpRow = {
  smtpProvider: string;
  smtpHost: string;
  smtpPort: number;
  smtpUsername: string;
  smtpSecretCipher: string;
  smtpSecretIv: string;
  smtpFromName: string;
  smtpEnabled: number;
  smtpVerifiedAt: string | null;
};

export type StoredSmtpConfig = {
  provider: SmtpProvider;
  host: string;
  port: number;
  username: string;
  secretCipher: string;
  secretIv: string;
  fromName: string;
  enabled: boolean;
  verifiedAt: string | null;
};

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

async function getEncryptionKey() {
  const keyValue = (
    env as typeof env & { SMTP_CONFIG_KEY?: string }
  ).SMTP_CONFIG_KEY;
  if (!keyValue || keyValue.length < 24) {
    throw new Error("服务器尚未配置 SMTP_CONFIG_KEY");
  }

  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(keyValue),
  );
  return crypto.subtle.importKey(
    "raw",
    digest,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptSmtpSecret(secret: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getEncryptionKey();
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(secret),
  );
  return {
    cipher: bytesToBase64(new Uint8Array(cipher)),
    iv: bytesToBase64(iv),
  };
}

export async function decryptSmtpSecret(cipher: string, iv: string) {
  if (!cipher || !iv) throw new Error("SMTP 授权码尚未保存");
  const key = await getEncryptionKey();
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(iv) },
    key,
    base64ToBytes(cipher),
  );
  return new TextDecoder().decode(plain);
}

export function normalizeSmtpProvider(value: unknown): SmtpProvider | null {
  const provider = String(value ?? "");
  return provider === "qq" || provider === "163" || provider === "gmail"
    ? provider
    : null;
}

export function validateSmtpUsername(
  provider: SmtpProvider,
  username: string,
) {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(username)) {
    return "请输入完整的发件邮箱地址";
  }
  const lower = username.toLowerCase();
  if (provider === "qq" && !lower.endsWith("@qq.com")) {
    return "QQ SMTP 发件账号需要使用 @qq.com 邮箱";
  }
  if (provider === "163" && !lower.endsWith("@163.com")) {
    return "163 SMTP 发件账号需要使用 @163.com 邮箱";
  }
  return "";
}

export async function getStoredSmtpConfig(): Promise<StoredSmtpConfig | null> {
  const row = await env.DB.prepare(
    `SELECT
      smtp_provider AS smtpProvider,
      smtp_host AS smtpHost,
      smtp_port AS smtpPort,
      smtp_username AS smtpUsername,
      smtp_secret_cipher AS smtpSecretCipher,
      smtp_secret_iv AS smtpSecretIv,
      smtp_from_name AS smtpFromName,
      smtp_enabled AS smtpEnabled,
      smtp_verified_at AS smtpVerifiedAt
    FROM security_settings
    WHERE id = 1`,
  ).first<StoredSmtpRow>();

  const provider = normalizeSmtpProvider(row?.smtpProvider);
  if (!row || !provider) return null;
  const preset = SMTP_PRESETS[provider];
  if (
    row.smtpHost !== preset.host ||
    Number(row.smtpPort) !== preset.port ||
    !row.smtpUsername
  ) {
    return null;
  }

  return {
    provider,
    host: preset.host,
    port: preset.port,
    username: row.smtpUsername,
    secretCipher: row.smtpSecretCipher,
    secretIv: row.smtpSecretIv,
    fromName: row.smtpFromName || "钥密",
    enabled: Boolean(row.smtpEnabled),
    verifiedAt: row.smtpVerifiedAt,
  };
}

export async function getReadySmtpConfig() {
  const config = await getStoredSmtpConfig();
  if (!config || !config.enabled || !config.secretCipher || !config.secretIv) {
    throw new Error("请先在设置中保存并测试 SMTP 邮件服务");
  }
  return {
    ...config,
    secret: await decryptSmtpSecret(config.secretCipher, config.secretIv),
  };
}
