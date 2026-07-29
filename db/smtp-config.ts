import { env } from "cloudflare:workers";

export type SmtpSecurity = "tls" | "starttls";

type StoredSmtpRow = {
  smtpProvider: string;
  smtpHost: string;
  smtpPort: number;
  smtpSecurity: string;
  smtpUsername: string;
  smtpSecretCipher: string;
  smtpSecretIv: string;
  smtpFromName: string;
  smtpEnabled: number;
  smtpFeatureEnabled: number;
  smtpVerifiedAt: string | null;
};

export type StoredSmtpConfig = {
  provider: string;
  host: string;
  port: number;
  security: SmtpSecurity;
  username: string;
  secretCipher: string;
  secretIv: string;
  fromName: string;
  enabled: boolean;
  featureEnabled: boolean;
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

export function normalizeSmtpProvider(value: unknown) {
  const provider = String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, 50);
  const presetNames: Record<string, string> = {
    qq: "QQ 邮箱",
    "qq 邮箱": "QQ 邮箱",
    "163": "163 邮箱",
    "163 邮箱": "163 邮箱",
    gmail: "Gmail",
  };
  return presetNames[provider.toLowerCase()] ?? provider;
}

export function normalizeSmtpSecurity(
  value: unknown,
): SmtpSecurity | null {
  const security = String(value ?? "").toLowerCase();
  return security === "tls" || security === "starttls" ? security : null;
}

export function normalizeSmtpHost(value: unknown) {
  const host = String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
  if (
    host.length < 4 ||
    host.length > 253 ||
    !host.includes(".") ||
    !/^[a-z0-9.-]+$/.test(host) ||
    host.includes("..") ||
    host.startsWith(".") ||
    host.endsWith(".") ||
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)
  ) {
    return null;
  }
  const validLabels = host.split(".").every(
    (label) =>
      label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
  );
  return validLabels ? host : null;
}

export function validateSmtpPort(value: unknown) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 25) {
    return null;
  }
  return port;
}

export function validateSmtpUsername(username: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(username)
    ? ""
    : "请输入完整的发件邮箱地址";
}

export async function getStoredSmtpConfig(): Promise<StoredSmtpConfig | null> {
  const row = await env.DB.prepare(
    `SELECT
      smtp_provider AS smtpProvider,
      smtp_host AS smtpHost,
      smtp_port AS smtpPort,
      smtp_security AS smtpSecurity,
      smtp_username AS smtpUsername,
      smtp_secret_cipher AS smtpSecretCipher,
      smtp_secret_iv AS smtpSecretIv,
      smtp_from_name AS smtpFromName,
      smtp_enabled AS smtpEnabled,
      smtp_feature_enabled AS smtpFeatureEnabled,
      smtp_verified_at AS smtpVerifiedAt
    FROM security_settings
    WHERE id = 1`,
  ).first<StoredSmtpRow>();

  if (!row) return null;
  const provider = normalizeSmtpProvider(row.smtpProvider);
  const host = normalizeSmtpHost(row.smtpHost);
  const port = validateSmtpPort(row.smtpPort);
  const security = normalizeSmtpSecurity(row.smtpSecurity);
  if (!provider || !host || !port || !security || !row.smtpUsername) {
    return null;
  }

  return {
    provider,
    host,
    port,
    security,
    username: row.smtpUsername,
    secretCipher: row.smtpSecretCipher,
    secretIv: row.smtpSecretIv,
    fromName: row.smtpFromName || "钥密",
    enabled: Boolean(row.smtpEnabled),
    featureEnabled: Boolean(row.smtpFeatureEnabled),
    verifiedAt: row.smtpVerifiedAt,
  };
}

export async function getReadySmtpConfig() {
  const config = await getStoredSmtpConfig();
  if (
    !config ||
    !config.featureEnabled ||
    !config.enabled ||
    !config.secretCipher ||
    !config.secretIv
  ) {
    throw new Error("请先启用、保存并测试 SMTP 邮件服务");
  }
  return {
    ...config,
    secret: await decryptSmtpSecret(config.secretCipher, config.secretIv),
  };
}
