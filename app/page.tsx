"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

type Phase = "locked" | "verify" | "vault";
type AppView = "vault" | "records" | "settings";
type RecoveryStep = "closed" | "code" | "email" | "sent";
type ThemePreference =
  | "dark"
  | "light"
  | "violet"
  | "glacier"
  | "amber"
  | "system";

type VaultEntry = {
  id: string;
  projectName: string;
  account: string;
  category: string;
  securityStatus: string;
  passwordCipher: string;
  passwordIv: string;
  notes: string;
  updatedAt: string;
  decryptionError?: boolean;
};

type VaultSecretPayload = {
  version: 2;
  projectName: string;
  account: string;
  category: string;
  notes: string;
  password: string;
};

type TrustedDevice = {
  id: string;
  deviceName: string;
  browser: string;
  location: string;
  lastActive: string;
  createdAt: string;
};

type VaultPayload = {
  entries: VaultEntry[];
  devices: TrustedDevice[];
  settings: {
    twoFactorEnabled: boolean;
    email: string;
    maxFailedAttempts: number;
    lockoutMinutes: number;
    smtpProvider: string;
    smtpHost: string;
    smtpPort: number;
    smtpSecurity: string;
    smtpUsername: string;
    smtpFromName: string;
    smtpEnabled: boolean;
    smtpFeatureEnabled: boolean;
    smtpVerifiedAt: string | null;
    requiresPasswordChange: boolean;
    usesLegacyDefaultEncryption: boolean;
    hasSmtpSecret: boolean;
  };
};

const DEMO_CODE = "246810";
const LEGACY_DEFAULT_RECORD_PASSWORD = "KeySafe2026!";
const ENCRYPTED_RECORD_PREFIX = "yv2.";
const encryptedStorageFields = {
  projectName: "加密记录",
  account: "••••••••",
  category: "已加密",
  notes: "",
};

const themeOptions: Array<{
  value: ThemePreference;
  label: string;
  description: string;
  icon: string;
}> = [
  {
    value: "dark",
    label: "深海深色",
    description: "经典安全深色界面",
    icon: "☾",
  },
  {
    value: "light",
    label: "薄荷浅色",
    description: "清爽柔和的浅色界面",
    icon: "☀",
  },
  {
    value: "violet",
    label: "银河紫",
    description: "紫色霓光科技氛围",
    icon: "◆",
  },
  {
    value: "glacier",
    label: "冰川蓝",
    description: "冷静明亮的蓝色界面",
    icon: "❄",
  },
  {
    value: "amber",
    label: "石墨琥珀",
    description: "沉稳温暖的金色质感",
    icon: "◉",
  },
  {
    value: "system",
    label: "跟随系统",
    description: "自动匹配当前设备",
    icon: "◐",
  },
];

const themeValues = themeOptions.map((option) => option.value);

const defaultPayload: VaultPayload = {
  entries: [],
  devices: [],
  settings: {
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
    requiresPasswordChange: true,
    usesLegacyDefaultEncryption: false,
    hasSmtpSecret: false,
  },
};

const smtpPresetOptions = [
  {
    aliases: ["qq", "qq 邮箱"],
    label: "QQ 邮箱",
    host: "smtp.qq.com",
    port: 465,
    security: "tls",
  },
  {
    aliases: ["163", "163 邮箱"],
    label: "163 邮箱",
    host: "smtp.163.com",
    port: 465,
    security: "tls",
  },
  {
    aliases: ["gmail"],
    label: "Gmail",
    host: "smtp.gmail.com",
    port: 465,
    security: "tls",
  },
] as const;

function findSmtpPreset(provider: string) {
  const normalized = provider.trim().toLowerCase();
  return smtpPresetOptions.find(
    (preset) =>
      preset.label.toLowerCase() === normalized ||
      preset.aliases.some((alias) => alias === normalized),
  );
}

function displaySmtpProvider(provider: string) {
  return findSmtpPreset(provider)?.label ?? provider;
}

const categoryTone: Record<string, string> = {
  开发工具: "blue",
  电子邮件: "cyan",
  服务器: "violet",
  金融: "green",
  社交: "orange",
};

const recommendedCategories = [
  "开发工具",
  "电子邮件",
  "服务器",
  "金融",
  "社交",
];

function isNotificationEmailConfigured(email: string) {
  return (
    !email.includes("*") &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  );
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(value: string) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

async function deriveVaultKey(masterPassword: string, salt: Uint8Array) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: 150_000,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptVaultRecord(
  payload: Omit<VaultSecretPayload, "version">,
  masterPassword: string,
) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(masterPassword, salt);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(JSON.stringify({ version: 2, ...payload })),
  );

  return {
    passwordCipher: `${ENCRYPTED_RECORD_PREFIX}${bytesToBase64(salt)}.${bytesToBase64(
      new Uint8Array(cipher),
    )}`,
    passwordIv: bytesToBase64(iv),
  };
}

async function decryptLegacySecret(
  passwordCipher: string,
  passwordIv: string,
  masterPassword: string,
) {
  const key = await deriveVaultKey(
    masterPassword,
    new TextEncoder().encode("yue-mi-vault-v1"),
  );
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(passwordIv) },
    key,
    base64ToBytes(passwordCipher),
  );

  return new TextDecoder().decode(plain);
}

async function decryptVaultRecord(
  passwordCipher: string,
  passwordIv: string,
  masterPassword: string,
) {
  if (!passwordCipher.startsWith(ENCRYPTED_RECORD_PREFIX)) {
    throw new Error("Unsupported encrypted record format");
  }

  const [saltValue, cipherValue] = passwordCipher
    .slice(ENCRYPTED_RECORD_PREFIX.length)
    .split(".");
  if (!saltValue || !cipherValue) {
    throw new Error("Invalid encrypted record");
  }

  const key = await deriveVaultKey(masterPassword, base64ToBytes(saltValue));
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(passwordIv) },
    key,
    base64ToBytes(cipherValue),
  );
  const payload = JSON.parse(
    new TextDecoder().decode(plain),
  ) as VaultSecretPayload;

  if (
    payload.version !== 2 ||
    !payload.projectName ||
    !payload.account ||
    !payload.category ||
    typeof payload.password !== "string" ||
    typeof payload.notes !== "string"
  ) {
    throw new Error("Invalid encrypted record payload");
  }

  return payload;
}

type ImportableEncryptedEntry = {
  passwordCipher: string;
  passwordIv: string;
};

type PasswordChangeEntry = ImportableEncryptedEntry & {
  id: string;
};

type BrowserPasswordRow = {
  projectName: string;
  account: string;
  category: string;
  notes: string;
  password: string;
};

type EncryptedBackupDocument = {
  format: "yuemi-encrypted-vault-backup";
  version: 1;
  createdAt: string;
  recordCount: number;
  kdf: {
    name: "PBKDF2";
    hash: "SHA-256";
    iterations: number;
    salt: string;
  };
  cipher: {
    name: "AES-GCM";
    iv: string;
    data: string;
  };
};

const BACKUP_KDF_ITERATIONS = 150_000;

async function deriveBackupKey(
  masterPassword: string,
  salt: Uint8Array,
  iterations: number,
) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptVaultRecordsBatch(
  records: BrowserPasswordRow[],
  masterPassword: string,
): Promise<ImportableEncryptedEntry[]> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveVaultKey(masterPassword, salt);
  const saltValue = bytesToBase64(salt);

  return Promise.all(
    records.map(async (record) => {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const cipher = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        new TextEncoder().encode(
          JSON.stringify({
            version: 2,
            projectName: record.projectName,
            account: record.account,
            category: record.category,
            notes: record.notes,
            password: record.password,
          } satisfies VaultSecretPayload),
        ),
      );
      return {
        passwordCipher: `${ENCRYPTED_RECORD_PREFIX}${saltValue}.${bytesToBase64(
          new Uint8Array(cipher),
        )}`,
        passwordIv: bytesToBase64(iv),
      };
    }),
  );
}

async function preparePasswordChangeEntries(
  entries: VaultEntry[],
  currentPassword: string,
  newPassword: string,
): Promise<PasswordChangeEntry[]> {
  const records = entries.filter(
    (entry) =>
      entry.passwordCipher !== "encrypted-demo-value" &&
      entry.passwordIv !== "demo-iv",
  );
  if (records.length > 2000) {
    throw new Error("单次最多可更新 2000 条密码记录");
  }
  if (records.some((entry) => entry.decryptionError)) {
    throw new Error("密码库中存在无法解密的记录，请重新登录后再修改");
  }

  const plainRecords = await Promise.all(
    records.map(async (entry) => {
      if (entry.passwordCipher.startsWith(ENCRYPTED_RECORD_PREFIX)) {
        return decryptVaultRecord(
          entry.passwordCipher,
          entry.passwordIv,
          currentPassword,
        );
      }
      return {
        version: 2 as const,
        projectName: entry.projectName,
        account: entry.account,
        category: entry.category,
        notes: entry.notes,
        password: await decryptLegacySecret(
          entry.passwordCipher,
          entry.passwordIv,
          currentPassword,
        ),
      };
    }),
  );

  const encryptedRecords = await encryptVaultRecordsBatch(
    plainRecords.map((record) => ({
      projectName: record.projectName,
      account: record.account,
      category: record.category,
      notes: record.notes,
      password: record.password,
    })),
    newPassword,
  );

  return encryptedRecords.map((record, index) => ({
    id: records[index].id,
    ...record,
  }));
}

function parseCsvRows(text: string) {
  const rows: string[][] = [];
  let row: string[] = [];
  let value = "";
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        value += '"';
        index += 1;
      } else if (character === '"') {
        quoted = false;
      } else {
        value += character;
      }
    } else if (character === '"') {
      quoted = true;
    } else if (character === ",") {
      row.push(value);
      value = "";
    } else if (character === "\n") {
      row.push(value.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      value = "";
    } else {
      value += character;
    }
  }

  if (value || row.length) {
    row.push(value.replace(/\r$/, ""));
    rows.push(row);
  }
  return rows.filter((columns) => columns.some((column) => column.trim()));
}

function parseBrowserPasswordCsv(text: string) {
  const rows = parseCsvRows(text.replace(/^\uFEFF/, ""));
  if (rows.length < 2) {
    throw new Error("CSV 中没有可导入的密码记录");
  }

  const headers = rows[0].map((header) => header.trim().toLowerCase());
  const findHeader = (...names: string[]) =>
    headers.findIndex((header) => names.includes(header));
  const nameIndex = findHeader("name", "title", "site", "网站", "名称");
  const urlIndex = findHeader("url", "website", "origin", "网址");
  const usernameIndex = findHeader(
    "username",
    "user",
    "login_username",
    "账号",
    "用户名",
  );
  const passwordIndex = findHeader("password", "密码");
  const noteIndex = findHeader("note", "notes", "备注");

  if (passwordIndex < 0) {
    throw new Error("无法识别 CSV：缺少 password 密码列");
  }

  const parsed = rows.slice(1).flatMap((columns, index) => {
    const password = columns[passwordIndex]?.trim() ?? "";
    if (!password) return [];
    const url = urlIndex >= 0 ? columns[urlIndex]?.trim() ?? "" : "";
    let projectName =
      nameIndex >= 0 ? columns[nameIndex]?.trim() ?? "" : "";
    if (!projectName && url) {
      try {
        projectName = new URL(url).hostname.replace(/^www\./, "");
      } catch {
        projectName = url.slice(0, 80);
      }
    }
    const originalNote =
      noteIndex >= 0 ? columns[noteIndex]?.trim() ?? "" : "";
    return [
      {
        projectName: (projectName || `浏览器密码 ${index + 1}`).slice(0, 120),
        account:
          (usernameIndex >= 0
            ? columns[usernameIndex]?.trim()
            : "") || "未填写账号",
        category: "浏览器导入",
        notes: [url ? `网址：${url}` : "", originalNote]
          .filter(Boolean)
          .join("\n")
          .slice(0, 2000),
        password,
      },
    ];
  });

  if (!parsed.length) {
    throw new Error("CSV 中没有包含密码的有效记录");
  }
  if (parsed.length > 1000) {
    throw new Error("单次最多导入 1000 条密码记录");
  }
  return parsed;
}

async function createEncryptedBackup(
  entries: VaultEntry[],
  masterPassword: string,
) {
  const records = entries
    .filter(
      (entry) =>
        !entry.decryptionError &&
        entry.passwordCipher.startsWith(ENCRYPTED_RECORD_PREFIX),
    )
    .map((entry) => ({
      passwordCipher: entry.passwordCipher,
      passwordIv: entry.passwordIv,
    }));
  if (!records.length) {
    throw new Error("当前没有可备份的加密密码记录");
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBackupKey(
    masterPassword,
    salt,
    BACKUP_KDF_ITERATIONS,
  );
  const plain = new TextEncoder().encode(
    JSON.stringify({
      format: "yuemi-vault-records",
      version: 1,
      records,
    }),
  );
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);

  return {
    backup: {
      format: "yuemi-encrypted-vault-backup",
      version: 1,
      createdAt: new Date().toISOString(),
      recordCount: records.length,
      kdf: {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations: BACKUP_KDF_ITERATIONS,
        salt: bytesToBase64(salt),
      },
      cipher: {
        name: "AES-GCM",
        iv: bytesToBase64(iv),
        data: bytesToBase64(new Uint8Array(cipher)),
      },
    } satisfies EncryptedBackupDocument,
    skipped: entries.length - records.length,
  };
}

async function decryptEncryptedBackup(
  text: string,
  masterPassword: string,
): Promise<ImportableEncryptedEntry[]> {
  let document: EncryptedBackupDocument;
  try {
    document = JSON.parse(text) as EncryptedBackupDocument;
  } catch {
    throw new Error("备份文件格式不正确");
  }
  if (
    document.format !== "yuemi-encrypted-vault-backup" ||
    document.version !== 1 ||
    document.kdf?.name !== "PBKDF2" ||
    document.kdf.hash !== "SHA-256" ||
    document.kdf.iterations !== BACKUP_KDF_ITERATIONS ||
    document.cipher?.name !== "AES-GCM"
  ) {
    throw new Error("不支持的钥密备份文件");
  }

  try {
    const key = await deriveBackupKey(
      masterPassword,
      base64ToBytes(document.kdf.salt),
      document.kdf.iterations,
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(document.cipher.iv) },
      key,
      base64ToBytes(document.cipher.data),
    );
    const payload = JSON.parse(new TextDecoder().decode(plain)) as {
      format?: string;
      version?: number;
      records?: ImportableEncryptedEntry[];
    };
    if (
      payload.format !== "yuemi-vault-records" ||
      payload.version !== 1 ||
      !Array.isArray(payload.records) ||
      !payload.records.length ||
      payload.records.length > 2000 ||
      payload.records.some(
        (record) =>
          typeof record.passwordCipher !== "string" ||
          !record.passwordCipher.startsWith(ENCRYPTED_RECORD_PREFIX) ||
          typeof record.passwordIv !== "string" ||
          !record.passwordIv,
      )
    ) {
      throw new Error("备份内容校验失败");
    }
    return payload.records;
  } catch (error) {
    if (error instanceof Error && error.message === "备份内容校验失败") {
      throw error;
    }
    throw new Error("备份解密失败，请确认主密码和文件是否正确");
  }
}

function downloadEncryptedBackup(
  backup: EncryptedBackupDocument,
  filename: string,
) {
  const blob = new Blob([JSON.stringify(backup, null, 2)], {
    type: "application/vnd.yuemi.vault+json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

async function hydrateVaultEntries(
  entries: VaultEntry[],
  masterPassword: string,
) {
  return Promise.all(
    entries.map(async (entry) => {
      if (!entry.passwordCipher.startsWith(ENCRYPTED_RECORD_PREFIX)) {
        return entry;
      }

      try {
        const payload = await decryptVaultRecord(
          entry.passwordCipher,
          entry.passwordIv,
          masterPassword,
        );
        return {
          ...entry,
          projectName: payload.projectName,
          account: payload.account,
          category: payload.category,
          notes: payload.notes,
        };
      } catch {
        return {
          ...entry,
          projectName: "无法解密的记录",
          account: "—",
          category: "已加密",
          notes: "请锁定密码库后重新输入主密码。",
          decryptionError: true,
        };
      }
    }),
  );
}

function makePassword(length: number, options: Record<string, boolean>) {
  const groups = [
    options.lowercase ? "abcdefghijkmnopqrstuvwxyz" : "",
    options.uppercase ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "",
    options.numbers ? "23456789" : "",
    options.symbols ? "!@#$%^&*_-+=" : "",
  ].filter(Boolean);
  const alphabet = groups.join("") || "abcdefghijkmnopqrstuvwxyz";
  const random = crypto.getRandomValues(new Uint32Array(length));
  const chars = Array.from(random, (value) => alphabet[value % alphabet.length]);

  groups.forEach((group, index) => {
    if (index < chars.length) {
      chars[index] = group[random[index] % group.length];
    }
  });

  return chars
    .map((char, index) => ({ char, order: random[index] }))
    .sort((a, b) => a.order - b.order)
    .map(({ char }) => char)
    .join("");
}

function ShieldMark({ small = false }: { small?: boolean }) {
  return <span className={small ? "shield-mark small" : "shield-mark"}>⌁</span>;
}

type MasterPasswordChangeHandler = (
  currentPassword: string,
  newPassword: string,
) => Promise<{ ok: boolean; error?: string }>;

function validateMasterPasswordChange(
  currentPassword: string,
  newPassword: string,
  confirmPassword: string,
) {
  const passwordGroups = [
    /[a-z]/.test(newPassword),
    /[A-Z]/.test(newPassword),
    /\d/.test(newPassword),
    /[^A-Za-z0-9]/.test(newPassword),
  ].filter(Boolean).length;

  if (!currentPassword) return "请输入当前主密码";
  if (newPassword.length < 10 || newPassword.length > 128) {
    return "新主密码长度需为 10–128 位";
  }
  if (passwordGroups < 3) {
    return "新主密码至少包含大写字母、小写字母、数字和符号中的三类";
  }
  if (newPassword !== confirmPassword) {
    return "两次输入的新主密码不一致";
  }
  if (newPassword === currentPassword) {
    return "新主密码不能与当前主密码相同";
  }
  return "";
}

export default function Home() {
  const [phase, setPhase] = useState<Phase>("locked");
  const [view, setView] = useState<AppView>("vault");
  const [vault, setVault] = useState<VaultPayload>(defaultPayload);
  const [masterPassword, setMasterPassword] = useState("");
  const [showMasterPassword, setShowMasterPassword] = useState(false);
  const [unlockError, setUnlockError] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [verificationError, setVerificationError] = useState("");
  const [verificationChallenge, setVerificationChallenge] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [sessionToken, setSessionToken] = useState("");
  const [toast, setToast] = useState("");
  const [loading, setLoading] = useState(false);
  const [lockedUntil, setLockedUntil] = useState<number | null>(null);
  const [lockoutRemaining, setLockoutRemaining] = useState(0);
  const [deleteTarget, setDeleteTarget] = useState<TrustedDevice | null>(null);
  const [theme, setTheme] = useState<ThemePreference>("system");
  const [themeLoaded, setThemeLoaded] = useState(false);
  const [recoveryAvailable, setRecoveryAvailable] = useState(false);
  const [recoveryMaskedEmail, setRecoveryMaskedEmail] = useState("");
  const [requiresInitialPasswordChange, setRequiresInitialPasswordChange] =
    useState(false);
  const [recoveryStep, setRecoveryStep] =
    useState<RecoveryStep>("closed");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [recoveryEmail, setRecoveryEmail] = useState("");
  const [recoveryToken, setRecoveryToken] = useState("");
  const [recoveryError, setRecoveryError] = useState("");

  const [passwordLength, setPasswordLength] = useState(20);
  const [passwordOptions, setPasswordOptions] = useState({
    numbers: true,
    uppercase: true,
    lowercase: true,
    symbols: true,
  });
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [entryForm, setEntryForm] = useState({
    projectName: "",
    account: "",
    category: "开发工具",
    password: "",
    notes: "",
  });

  const fetchVault = useCallback(
    async (token: string, unlockPassword: string) => {
      try {
        const response = await fetch("/api/vault", {
          cache: "no-store",
          headers: { authorization: `Bearer ${token}` },
        });
        if (!response.ok) throw new Error("vault request failed");
        const payload = (await response.json()) as VaultPayload;
        const entries = await hydrateVaultEntries(
          payload.entries,
          payload.settings.usesLegacyDefaultEncryption
            ? LEGACY_DEFAULT_RECORD_PASSWORD
            : unlockPassword,
        );
        const hydratedPayload = { ...payload, entries };
        setVault(hydratedPayload);
        return hydratedPayload;
      } catch {
        setToast("暂时无法读取密码库，请稍后重试");
        return null;
      }
    },
    [],
  );

  const refreshRecoveryStatus = useCallback(async () => {
    try {
      const response = await fetch("/api/auth/recovery", {
        cache: "no-store",
      });
      if (!response.ok) throw new Error("recovery status failed");
      const result = (await response.json()) as {
        configured?: boolean;
        maskedEmail?: string;
        requiresPasswordChange?: boolean;
      };
      setRecoveryAvailable(Boolean(result.configured));
      setRecoveryMaskedEmail(result.maskedEmail ?? "");
      setRequiresInitialPasswordChange(
        Boolean(result.requiresPasswordChange),
      );
    } catch {
      setRecoveryAvailable(false);
      setRecoveryMaskedEmail("");
      setRequiresInitialPasswordChange(false);
    }
  }, []);

  useEffect(() => {
    let localDeviceId = window.localStorage.getItem("yuemi-device-id");
    if (!localDeviceId) {
      localDeviceId = crypto.randomUUID();
      window.localStorage.setItem("yuemi-device-id", localDeviceId);
    }
    setDeviceId(localDeviceId);
    setGeneratedPassword(
      makePassword(passwordLength, {
        numbers: true,
        uppercase: true,
        lowercase: true,
        symbols: true,
      }),
    );
  }, []);

  useEffect(() => {
    void refreshRecoveryStatus();
  }, [refreshRecoveryStatus]);

  useEffect(() => {
    const savedTheme = window.localStorage.getItem("yuemi-theme");
    if (themeValues.includes(savedTheme as ThemePreference)) {
      setTheme(savedTheme as ThemePreference);
    }
    setThemeLoaded(true);
  }, []);

  useEffect(() => {
    if (!themeLoaded) return;

    const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
    const applyTheme = () => {
      const resolvedTheme =
        theme === "system" ? (systemTheme.matches ? "dark" : "light") : theme;
      document.documentElement.dataset.theme = resolvedTheme;
      document.documentElement.dataset.themePreference = theme;
      document.documentElement.style.colorScheme =
        resolvedTheme === "light" || resolvedTheme === "glacier"
          ? "light"
          : "dark";
    };

    applyTheme();
    window.localStorage.setItem("yuemi-theme", theme);
    systemTheme.addEventListener("change", applyTheme);
    return () => systemTheme.removeEventListener("change", applyTheme);
  }, [theme, themeLoaded]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    if (!lockedUntil) {
      setLockoutRemaining(0);
      return;
    }

    const updateRemaining = () => {
      const remaining = Math.max(
        0,
        Math.ceil((lockedUntil - Date.now()) / 1000),
      );
      setLockoutRemaining(remaining);
      if (!remaining) setLockedUntil(null);
    };
    updateRemaining();
    const timer = window.setInterval(updateRemaining, 1000);
    return () => window.clearInterval(timer);
  }, [lockedUntil]);

  const regenerate = useCallback(() => {
    setGeneratedPassword(makePassword(passwordLength, passwordOptions));
  }, [passwordLength, passwordOptions]);

  useEffect(() => {
    if (generatedPassword) regenerate();
    // Regenerate only when the password rules change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [passwordLength, passwordOptions]);

  async function postVault(body: Record<string, unknown>) {
    const response = await fetch("/api/vault", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${sessionToken}`,
      },
      body: JSON.stringify(body),
    });
    const result = (await response.json().catch(() => ({}))) as {
      error?: string;
      [key: string]: unknown;
    };
    if (response.status === 401) {
      setSessionToken("");
      setVault(defaultPayload);
      setPhase("locked");
      throw new Error("本次访问已过期，请重新输入主密码");
    }
    if (!response.ok) throw new Error(result.error ?? "保存失败");
    return result;
  }

  async function handleUnlock(event: FormEvent) {
    event.preventDefault();
    if (lockoutRemaining > 0) return;
    setUnlockError("");
    setLoading(true);
    try {
      const response = await fetch("/api/auth/unlock", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          deviceId,
          masterPassword,
          deviceName: "Windows 桌面设备",
          browser: "Codex 浏览器",
          location: "当前网络",
        }),
      });
      const result = (await response.json()) as {
        error?: string;
        attemptsRemaining?: number;
        lockedUntil?: string;
        remainingSeconds?: number;
        needsVerification?: boolean;
        challengeToken?: string;
        email?: string;
        sessionToken?: string;
      };

      if (!response.ok) {
        if (response.status === 423) {
          const lockTimestamp = result.lockedUntil
            ? Date.parse(result.lockedUntil)
            : Date.now() + (result.remainingSeconds ?? 60) * 1000;
          setLockedUntil(lockTimestamp);
        }
        const attempts =
          typeof result.attemptsRemaining === "number"
            ? `，还可尝试 ${result.attemptsRemaining} 次`
            : "";
        setUnlockError(`${result.error ?? "服务端校验失败"}${attempts}`);
        return;
      }

      if (result.needsVerification && result.challengeToken) {
        setVerificationChallenge(result.challengeToken);
        setVault((current) => ({
          ...current,
          settings: {
            ...current.settings,
            email: result.email ?? current.settings.email,
          },
        }));
        setPhase("verify");
        return;
      }

      if (!result.sessionToken) {
        setUnlockError("服务端未返回访问凭证，请重试");
        return;
      }

      setSessionToken(result.sessionToken);
      const loadedVault = await fetchVault(
        result.sessionToken,
        masterPassword,
      );
      if (loadedVault?.settings.requiresPasswordChange) {
        setView("settings");
      }
      setPhase("vault");
      setToast("服务端校验通过");
    } catch {
      setUnlockError("暂时无法连接验证服务，请稍后重试");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(event: FormEvent) {
    event.preventDefault();
    setVerificationError("");
    setLoading(true);
    try {
      const response = await fetch("/api/auth/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          code: verificationCode,
          challengeToken: verificationChallenge,
          deviceId,
          deviceName: "Windows 桌面设备",
          browser: "Codex 浏览器",
          location: "当前网络",
        }),
      });
      const result = (await response.json()) as {
        error?: string;
        sessionToken?: string;
      };
      if (!response.ok || !result.sessionToken) {
        setVerificationError(result.error ?? "设备验证失败，请稍后重试");
        return;
      }

      setSessionToken(result.sessionToken);
      const loadedVault = await fetchVault(
        result.sessionToken,
        masterPassword,
      );
      if (loadedVault?.settings.requiresPasswordChange) {
        setView("settings");
      }
      setPhase("vault");
      setToast("新设备验证成功");
    } catch {
      setVerificationError("设备验证失败，请稍后重试");
    } finally {
      setLoading(false);
    }
  }

  async function handleAddEntry(event: FormEvent) {
    event.preventDefault();
    if (!entryForm.projectName || !entryForm.account || !entryForm.password) {
      setToast("请填写项目名称、账号和密码");
      return;
    }

    try {
      const encrypted = await encryptVaultRecord(
        {
          projectName: entryForm.projectName,
          account: entryForm.account,
          category: entryForm.category,
          notes: entryForm.notes,
          password: entryForm.password,
        },
        masterPassword,
      );
      await postVault({
        action: "add-entry",
        ...encryptedStorageFields,
        ...encrypted,
      });
      setEntryForm({
        projectName: "",
        account: "",
        category: "开发工具",
        password: "",
        notes: "",
      });
      await fetchVault(sessionToken, masterPassword);
      setToast("记录已完整加密保存");
    } catch {
      setToast("保存失败，请稍后重试");
    }
  }

  async function handleImportEncryptedEntries(
    entries: ImportableEncryptedEntry[],
  ) {
    const result = await postVault({
      action: "import-entries",
      entries,
    });
    const imported = Number(result.imported ?? 0);
    await fetchVault(sessionToken, masterPassword);
    setToast(`已安全导入 ${imported} 条密码记录`);
    return imported;
  }

  async function handleUpdateEntry(
    id: string,
    values: {
      projectName: string;
      account: string;
      category: string;
      password: string;
      notes: string;
    },
  ) {
    if (!values.projectName || !values.account || !values.category) {
      setToast("请填写项目名称、账号和分类");
      return false;
    }

    try {
      const currentEntry = vault.entries.find((entry) => entry.id === id);
      let nextPassword = values.password;

      if (!nextPassword && currentEntry) {
        if (
          currentEntry.passwordCipher.startsWith(ENCRYPTED_RECORD_PREFIX)
        ) {
          const payload = await decryptVaultRecord(
            currentEntry.passwordCipher,
            currentEntry.passwordIv,
            masterPassword,
          );
          nextPassword = payload.password;
        } else if (
          currentEntry.passwordCipher !== "encrypted-demo-value" &&
          currentEntry.passwordIv !== "demo-iv"
        ) {
          nextPassword = await decryptLegacySecret(
            currentEntry.passwordCipher,
            currentEntry.passwordIv,
            masterPassword,
          );
        }
      }

      const encrypted = nextPassword
        ? await encryptVaultRecord(
            {
              projectName: values.projectName,
              account: values.account,
              category: values.category,
              notes: values.notes,
              password: nextPassword,
            },
            masterPassword,
          )
        : null;
      await postVault({
        action: "update-entry",
        id,
        ...(encrypted
          ? encryptedStorageFields
          : {
              projectName: values.projectName,
              account: values.account,
              category: values.category,
              notes: values.notes,
            }),
        ...(encrypted ?? {}),
      });
      await fetchVault(sessionToken, masterPassword);
      setToast("密码记录已更新");
      return true;
    } catch {
      setToast("修改失败，请稍后重试");
      return false;
    }
  }

  async function handleChangeMasterPassword(
    currentPassword: string,
    newPassword: string,
  ) {
    try {
      const entries = await preparePasswordChangeEntries(
        vault.entries,
        vault.settings.usesLegacyDefaultEncryption
          ? LEGACY_DEFAULT_RECORD_PASSWORD
          : currentPassword,
        newPassword,
      );
      await postVault({
        action: "change-master-password",
        currentPassword,
        newPassword,
        entries,
      });

      setMasterPassword("");
      setSessionToken("");
      setVault(defaultPayload);
      setView("vault");
      setPhase("locked");
      setShowMasterPassword(false);
      setRequiresInitialPasswordChange(false);
      setToast("主密码已修改，请使用新主密码重新登录");
      return { ok: true };
    } catch (error) {
      const message =
        error instanceof DOMException && error.name === "OperationError"
          ? "当前主密码不正确，无法解密现有密码记录"
          : error instanceof Error
            ? error.message
            : "主密码修改失败";
      setToast(message);
      return { ok: false, error: message };
    }
  }

  async function handleToggleTwoFactor() {
    if (
      !vault.settings.twoFactorEnabled &&
      !isNotificationEmailConfigured(vault.settings.email)
    ) {
      setToast("请先在登录保护中保存通知邮箱");
      return;
    }
    if (
      !vault.settings.twoFactorEnabled &&
      (!vault.settings.smtpFeatureEnabled || !vault.settings.smtpEnabled)
    ) {
      setToast("请先保存 SMTP 配置并发送测试邮件");
      return;
    }
    try {
      await postVault({
        action: "set-two-factor",
        enabled: !vault.settings.twoFactorEnabled,
      });
      await fetchVault(sessionToken, masterPassword);
      setToast(
        vault.settings.twoFactorEnabled
          ? "新设备二次验证已关闭"
          : "新设备二次验证已开启",
      );
    } catch (error) {
      setToast(error instanceof Error ? error.message : "设置更新失败");
    }
  }

  async function handleLockoutPolicy(
    maxFailedAttempts: number,
    lockoutMinutes: number,
  ) {
    try {
      await postVault({
        action: "set-lockout-policy",
        maxFailedAttempts,
        lockoutMinutes,
      });
      await fetchVault(sessionToken, masterPassword);
      setToast("密码错误锁定策略已更新");
    } catch {
      setToast("锁定策略更新失败");
    }
  }

  async function handleSaveRecoveryEmail(email: string) {
    const normalizedEmail = email.trim().toLowerCase();
    if (
      normalizedEmail &&
      !isNotificationEmailConfigured(normalizedEmail)
    ) {
      setToast("请输入有效的通知邮箱");
      return false;
    }

    try {
      await postVault({
        action: "set-recovery-email",
        email: normalizedEmail,
      });
      await fetchVault(sessionToken, masterPassword);
      await refreshRecoveryStatus();
      setToast(
        normalizedEmail
          ? "通知邮箱已保存，登录页找回入口已开启"
          : "通知邮箱已移除，登录页找回入口已关闭",
      );
      return true;
    } catch {
      setToast("通知邮箱保存失败");
      return false;
    }
  }

  async function handleSaveSmtpConfig(config: {
    provider: string;
    host: string;
    port: number;
    security: string;
    username: string;
    secret: string;
    fromName: string;
  }) {
    try {
      await postVault({ action: "set-smtp-config", ...config });
      await fetchVault(sessionToken, masterPassword);
      await refreshRecoveryStatus();
      setToast("SMTP 配置已加密保存，请发送测试邮件");
      return true;
    } catch (error) {
      setToast(error instanceof Error ? error.message : "SMTP 配置保存失败");
      return false;
    }
  }

  async function handleToggleSmtpFeature() {
    const enabled = !vault.settings.smtpFeatureEnabled;
    try {
      await postVault({ action: "set-smtp-feature", enabled });
      await fetchVault(sessionToken, masterPassword);
      await refreshRecoveryStatus();
      setToast(
        enabled
          ? "SMTP 邮件服务已开启，请填写并测试配置"
          : "SMTP 邮件服务已关闭",
      );
    } catch (error) {
      setToast(
        error instanceof Error ? error.message : "SMTP 邮件服务更新失败",
      );
    }
  }

  async function handleTestSmtp() {
    try {
      await postVault({ action: "test-smtp" });
      await fetchVault(sessionToken, masterPassword);
      await refreshRecoveryStatus();
      setToast("测试邮件已发送，SMTP 服务已启用");
      return true;
    } catch (error) {
      setToast(error instanceof Error ? error.message : "测试邮件发送失败");
      return false;
    }
  }

  async function openRecovery() {
    setRecoveryCode("");
    setRecoveryEmail("");
    setRecoveryToken("");
    setRecoveryError("");
    setLoading(true);
    try {
      const response = await fetch("/api/auth/recovery", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "request-code" }),
      });
      const result = (await response.json()) as {
        error?: string;
        sent?: boolean;
        maskedEmail?: string;
      };
      if (!response.ok || !result.sent) {
        setUnlockError(result.error ?? "找回验证码发送失败");
        return;
      }
      setRecoveryMaskedEmail(result.maskedEmail ?? recoveryMaskedEmail);
      setRecoveryStep("code");
    } catch {
      setUnlockError("找回验证码发送失败，请稍后重试");
    } finally {
      setLoading(false);
    }
  }

  function closeRecovery() {
    setRecoveryStep("closed");
    setRecoveryCode("");
    setRecoveryEmail("");
    setRecoveryToken("");
    setRecoveryError("");
  }

  async function handleRecoveryCode(event: FormEvent) {
    event.preventDefault();
    setRecoveryError("");
    setLoading(true);
    try {
      const response = await fetch("/api/auth/recovery", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action: "verify-code",
          code: recoveryCode,
        }),
      });
      const result = (await response.json()) as {
        error?: string;
        recoveryToken?: string;
        maskedEmail?: string;
      };
      if (!response.ok || !result.recoveryToken) {
        setRecoveryError(result.error ?? "两步验证失败");
        return;
      }
      setRecoveryToken(result.recoveryToken);
      setRecoveryMaskedEmail(result.maskedEmail ?? recoveryMaskedEmail);
      setRecoveryStep("email");
    } catch {
      setRecoveryError("暂时无法连接验证服务，请稍后重试");
    } finally {
      setLoading(false);
    }
  }

  async function handleRecoveryEmail(event: FormEvent) {
    event.preventDefault();
    setRecoveryError("");
    setLoading(true);
    try {
      const response = await fetch("/api/auth/recovery", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action: "send-password",
          email: recoveryEmail.trim(),
          recoveryToken,
        }),
      });
      const result = (await response.json()) as {
        error?: string;
        delivered?: boolean;
      };
      if (!response.ok || !result.delivered) {
        setRecoveryError(result.error ?? "通知邮箱验证失败");
        return;
      }
      setRequiresInitialPasswordChange(true);
      setRecoveryStep("sent");
    } catch {
      setRecoveryError("新主密码发送失败，请稍后重试");
    } finally {
      setLoading(false);
    }
  }

  async function confirmDeviceDeletion() {
    if (!deleteTarget) return;
    try {
      await postVault({ action: "delete-device", id: deleteTarget.id });
      const removedCurrentDevice = deleteTarget.id === deviceId;
      setDeleteTarget(null);
      await fetchVault(sessionToken, masterPassword);
      if (removedCurrentDevice) {
        const nextDeviceId = crypto.randomUUID();
        window.localStorage.setItem("yuemi-device-id", nextDeviceId);
        setDeviceId(nextDeviceId);
        setSessionToken("");
        setVault(defaultPayload);
        setMasterPassword("");
        setPhase("locked");
        setView("vault");
        setToast("当前设备已移除，请重新验证");
      } else {
        setToast("设备已从可信列表中删除");
      }
    } catch {
      setToast("设备删除失败");
    }
  }

  async function copyGeneratedPassword() {
    await navigator.clipboard.writeText(generatedPassword);
    setToast("密码已复制到剪贴板");
  }

  if (phase === "locked") {
    return (
      <main className="auth-shell">
        <section className="auth-card" aria-labelledby="unlock-title">
          <div className="brand-lockup">
            <ShieldMark />
            <span>钥密</span>
          </div>
          <div className="auth-heading">
            <span className="eyebrow">安全密码管理器</span>
            <h1 id="unlock-title">解锁钥密</h1>
            <p>请输入主密码进入你的加密密码库</p>
          </div>
          <div className="server-check-note">
            <span aria-hidden="true" />
            每次进入都会由服务端重新校验
          </div>
          <form onSubmit={handleUnlock} className="auth-form">
            <label htmlFor="master-password">主密码</label>
            <div className="input-with-icon">
              <input
                id="master-password"
                data-testid="master-password"
                type={showMasterPassword ? "text" : "password"}
                autoComplete="current-password"
                value={masterPassword}
                onChange={(event) => setMasterPassword(event.target.value)}
                placeholder="输入主密码"
              />
              <button
                className={`password-visibility-button${
                  showMasterPassword ? " is-visible" : ""
                }`}
                type="button"
                aria-label={
                  showMasterPassword ? "隐藏主密码" : "显示主密码"
                }
                aria-pressed={showMasterPassword}
                title={showMasterPassword ? "隐藏主密码" : "显示主密码"}
                onClick={() =>
                  setShowMasterPassword((current) => !current)
                }
              >
                <span className="password-eye" aria-hidden="true" />
              </button>
            </div>
            {unlockError ? <p className="form-error">{unlockError}</p> : null}
            <button
              className="primary-button"
              type="submit"
              disabled={loading || lockoutRemaining > 0}
            >
              {lockoutRemaining > 0
                ? `已锁定 ${Math.floor(lockoutRemaining / 60)}:${String(
                    lockoutRemaining % 60,
                  ).padStart(2, "0")}`
                : loading
                  ? "服务端校验中…"
                  : "解锁并进入"}
            </button>
          </form>
          {recoveryAvailable ? (
            <button
              className="text-button"
              type="button"
              onClick={openRecovery}
            >
              忘记主密码？
            </button>
          ) : null}
          {requiresInitialPasswordChange ? (
            <div className="demo-hint">
              <span>首次登录默认密码（登录后必须修改）</span>
              <strong>12345678</strong>
            </div>
          ) : null}
          <div className="security-note">
            <ShieldMark small />
            <div>
              <strong>服务端访问门禁已开启</strong>
              <span>校验成功后才能读取加密密码库</span>
            </div>
          </div>
        </section>
        {recoveryStep !== "closed" ? (
          <div className="modal-backdrop" role="presentation">
            <section
              className="confirm-modal recovery-modal"
              role="dialog"
              aria-modal="true"
              aria-labelledby="recovery-title"
            >
              <button
                className="modal-close recovery-close"
                type="button"
                aria-label="关闭找回主密码"
                onClick={closeRecovery}
              >
                ×
              </button>
              {recoveryStep === "code" ? (
                <>
                  <span className="recovery-step">步骤 1 / 2 · 两步验证</span>
                  <h2 id="recovery-title">验证安全验证码</h2>
                  <p>验证码正确后，才能核对设置中保存的通知邮箱。</p>
                  <form className="auth-form" onSubmit={handleRecoveryCode}>
                    <label htmlFor="recovery-code">两步验证码</label>
                    <input
                      id="recovery-code"
                      className="code-input"
                      inputMode="numeric"
                      maxLength={6}
                      value={recoveryCode}
                      onChange={(event) =>
                        setRecoveryCode(event.target.value.replace(/\D/g, ""))
                      }
                      placeholder="••••••"
                      autoFocus
                    />
                    {recoveryError ? (
                      <p className="form-error">{recoveryError}</p>
                    ) : null}
                    <button
                      className="primary-button"
                      type="submit"
                      disabled={loading || recoveryCode.length !== 6}
                    >
                      {loading ? "验证中…" : "验证并继续"}
                    </button>
                  </form>
                  <div className="demo-hint recovery-demo-hint">
                    <span>演示验证码</span>
                    <strong>{DEMO_CODE}</strong>
                  </div>
                </>
              ) : null}
              {recoveryStep === "email" ? (
                <>
                  <span className="recovery-step">步骤 2 / 2 · 邮箱确认</span>
                  <h2 id="recovery-title">输入通知邮箱</h2>
                  <p>
                    请输入设置中保存的完整邮箱
                    {recoveryMaskedEmail
                      ? `（${recoveryMaskedEmail}）`
                      : ""}
                    ，一致后才会发送新主密码。
                  </p>
                  <form className="auth-form" onSubmit={handleRecoveryEmail}>
                    <label htmlFor="recovery-email">通知邮箱</label>
                    <input
                      id="recovery-email"
                      type="email"
                      autoComplete="email"
                      value={recoveryEmail}
                      onChange={(event) =>
                        setRecoveryEmail(event.target.value)
                      }
                      placeholder="输入设置中的通知邮箱"
                      autoFocus
                    />
                    {recoveryError ? (
                      <p className="form-error">{recoveryError}</p>
                    ) : null}
                    <button
                      className="primary-button"
                      type="submit"
                      disabled={loading || !recoveryEmail.trim()}
                    >
                      {loading ? "发送中…" : "发送新的主密码"}
                    </button>
                  </form>
                </>
              ) : null}
              {recoveryStep === "sent" ? (
                <div className="recovery-success">
                  <span className="recovery-success-mark" aria-hidden="true">
                    ✓
                  </span>
                  <span className="recovery-step">邮件发送完成</span>
                  <h2 id="recovery-title">新主密码已发送</h2>
                  <p>
                    通知邮箱验证成功，请前往邮箱查看新的主密码。
                  </p>
                  <button
                    className="primary-button"
                    type="button"
                    onClick={() => {
                      closeRecovery();
                    }}
                  >
                    返回登录
                  </button>
                </div>
              ) : null}
            </section>
          </div>
        ) : null}
      </main>
    );
  }

  if (phase === "verify") {
    return (
      <main className="auth-shell">
        <section className="auth-card verify-card" aria-labelledby="verify-title">
          <div className="brand-lockup">
            <ShieldMark />
            <span>钥密</span>
          </div>
          <div className="device-illustration" aria-hidden="true">
            <span>▣</span>
            <ShieldMark small />
          </div>
          <div className="auth-heading centered">
            <span className="eyebrow">检测到一台新设备</span>
            <h1 id="verify-title">验证新设备</h1>
            <p>我们已向你的邮箱发送 6 位验证码</p>
            <strong className="verified-email">{vault.settings.email}</strong>
          </div>
          <form onSubmit={handleVerify} className="auth-form">
            <label htmlFor="email-code">邮箱验证码</label>
            <input
              id="email-code"
              data-testid="email-code"
              className="code-input"
              inputMode="numeric"
              maxLength={6}
              value={verificationCode}
              onChange={(event) =>
                setVerificationCode(event.target.value.replace(/\D/g, ""))
              }
              placeholder="••••••"
            />
            <div className="form-row">
              <span>未收到验证码？</span>
              <button type="button" className="text-button compact">
                重新发送 00:42
              </button>
            </div>
            {verificationError ? (
              <p className="form-error">{verificationError}</p>
            ) : null}
            <button className="primary-button" type="submit">
              验证并继续
            </button>
            <button
              className="secondary-button"
              type="button"
              onClick={() => setPhase("locked")}
            >
              返回
            </button>
          </form>
          <div className="demo-hint">
            <span>演示验证码</span>
            <strong>{DEMO_CODE}</strong>
          </div>
        </section>
      </main>
    );
  }

  const requiresPasswordChange = vault.settings.requiresPasswordChange;

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup sidebar-brand">
          <ShieldMark />
          <span>钥密</span>
        </div>
        <nav aria-label="主要导航">
          <button
            className={
              !requiresPasswordChange && view === "vault"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setView("vault")}
            disabled={requiresPasswordChange}
          >
            <span>▣</span>密码库
          </button>
          <button
            className={
              !requiresPasswordChange && view === "records"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setView("records")}
            disabled={requiresPasswordChange}
          >
            <span>▤</span>密码记录
          </button>
          <button
            className={
              requiresPasswordChange || view === "settings"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setView("settings")}
            disabled={requiresPasswordChange}
          >
            <span>⚙</span>设置
          </button>
        </nav>
        <div className="sidebar-security">
          <ShieldMark small />
          <div>
            <strong>数据已加密保护</strong>
            <span>云端仅保存密文</span>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <span className="eyebrow">
              {requiresPasswordChange
                ? "首次使用 / 安全"
                : view === "settings"
                ? "设置 / 安全"
                : view === "records"
                  ? "安全记录"
                  : "个人密码空间"}
            </span>
            <h1>
              {requiresPasswordChange
                ? "修改默认主密码"
                : view === "settings"
                ? "安全设置"
                : view === "records"
                  ? "密码记录"
                  : "密码库"}
            </h1>
          </div>
          <div className="topbar-actions">
            <button
              className="theme-quick-button"
              type="button"
              aria-label={`切换界面主题，当前为${
                themeOptions.find((option) => option.value === theme)?.label
              }`}
              title="切换界面主题"
              onClick={() => {
                const currentIndex = themeValues.indexOf(theme);
                setTheme(themeValues[(currentIndex + 1) % themeValues.length]);
              }}
            >
              <span aria-hidden="true">
                {
                  themeOptions.find((option) => option.value === theme)
                    ?.icon
                }
              </span>
            </button>
            <span className="status-pill">
              <i />
              已安全连接
            </span>
            <button
              className="avatar"
              type="button"
              aria-label="锁定密码库"
              onClick={() => {
                setMasterPassword("");
                setSessionToken("");
                setVault(defaultPayload);
                setPhase("locked");
              }}
            >
              W
            </button>
          </div>
        </header>

        {requiresPasswordChange ? (
          <ForcedPasswordChangeView
            handleChangeMasterPassword={handleChangeMasterPassword}
          />
        ) : view !== "settings" ? (
          <VaultView
            vault={vault}
            recordsOnly={view === "records"}
            masterPassword={masterPassword}
            passwordLength={passwordLength}
            setPasswordLength={setPasswordLength}
            passwordOptions={passwordOptions}
            setPasswordOptions={setPasswordOptions}
            generatedPassword={generatedPassword}
            regenerate={regenerate}
            copyGeneratedPassword={copyGeneratedPassword}
            entryForm={entryForm}
            setEntryForm={setEntryForm}
            handleAddEntry={handleAddEntry}
            handleUpdateEntry={handleUpdateEntry}
          />
        ) : (
          <SettingsView
            vault={vault}
            deviceId={deviceId}
            theme={theme}
            setTheme={setTheme}
            masterPassword={masterPassword}
            handleImportEncryptedEntries={handleImportEncryptedEntries}
            handleChangeMasterPassword={handleChangeMasterPassword}
            handleToggleTwoFactor={handleToggleTwoFactor}
            handleLockoutPolicy={handleLockoutPolicy}
            handleSaveRecoveryEmail={handleSaveRecoveryEmail}
            handleSaveSmtpConfig={handleSaveSmtpConfig}
            handleToggleSmtpFeature={handleToggleSmtpFeature}
            handleTestSmtp={handleTestSmtp}
            setDeleteTarget={setDeleteTarget}
          />
        )}
      </section>

      {deleteTarget ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="confirm-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-device-title"
          >
            <span className="warning-mark" aria-hidden="true">
              !
            </span>
            <h2 id="delete-device-title">删除已加入的设备？</h2>
            <p>
              删除“{deleteTarget.deviceName}
              ”后，该设备下次进入时需要重新完成邮箱验证。
            </p>
            <div className="modal-actions">
              <button
                className="secondary-button"
                type="button"
                onClick={() => setDeleteTarget(null)}
              >
                取消
              </button>
              <button
                className="danger-button"
                data-testid="confirm-delete-device"
                type="button"
                onClick={confirmDeviceDeletion}
              >
                确认删除
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {toast ? (
        <div className="toast" role="status">
          <span>✓</span>
          {toast}
        </div>
      ) : null}
    </main>
  );
}

type VaultViewProps = {
  vault: VaultPayload;
  recordsOnly: boolean;
  masterPassword: string;
  passwordLength: number;
  setPasswordLength: (value: number) => void;
  passwordOptions: Record<string, boolean>;
  setPasswordOptions: React.Dispatch<
    React.SetStateAction<{
      numbers: boolean;
      uppercase: boolean;
      lowercase: boolean;
      symbols: boolean;
    }>
  >;
  generatedPassword: string;
  regenerate: () => void;
  copyGeneratedPassword: () => void;
  entryForm: {
    projectName: string;
    account: string;
    category: string;
    password: string;
    notes: string;
  };
  setEntryForm: React.Dispatch<
    React.SetStateAction<{
      projectName: string;
      account: string;
      category: string;
      password: string;
      notes: string;
    }>
  >;
  handleAddEntry: (event: FormEvent) => void;
  handleUpdateEntry: (
    id: string,
    values: {
      projectName: string;
      account: string;
      category: string;
      password: string;
      notes: string;
    },
  ) => Promise<boolean>;
};

function PasswordLengthInput({
  value,
  onChange,
}: {
  value: number;
  onChange: (value: number) => void;
}) {
  const [draft, setDraft] = useState(String(value));

  useEffect(() => {
    setDraft(String(value));
  }, [value]);

  function commitDraft() {
    const parsed = Number.parseInt(draft, 10);
    const nextValue = Number.isNaN(parsed)
      ? value
      : Math.min(30, Math.max(2, parsed));
    setDraft(String(nextValue));
    onChange(nextValue);
  }

  return (
    <input
      className="length-number"
      type="number"
      inputMode="numeric"
      min="2"
      max="30"
      step="1"
      aria-label="密码长度数值"
      value={draft}
      onFocus={(event) => event.currentTarget.select()}
      onChange={(event) => {
        const nextDraft = event.target.value.replace(/\D/g, "").slice(0, 2);
        setDraft(nextDraft);
        const nextValue = Number.parseInt(nextDraft, 10);
        if (nextValue >= 2 && nextValue <= 30) {
          onChange(nextValue);
        }
      }}
      onBlur={commitDraft}
      onKeyDown={(event) => {
        if (event.key === "Enter") event.currentTarget.blur();
        if (event.key === "Escape") {
          setDraft(String(value));
          event.currentTarget.blur();
        }
      }}
    />
  );
}

function VaultView({
  vault,
  recordsOnly,
  masterPassword,
  passwordLength,
  setPasswordLength,
  passwordOptions,
  setPasswordOptions,
  generatedPassword,
  regenerate,
  copyGeneratedPassword,
  entryForm,
  setEntryForm,
  handleAddEntry,
  handleUpdateEntry,
}: VaultViewProps) {
  const [revealedSecret, setRevealedSecret] = useState<{
    entry: VaultEntry;
    password: string;
    error: string;
  } | null>(null);
  const [revealingId, setRevealingId] = useState("");
  const [passwordCopied, setPasswordCopied] = useState(false);
  const [accountCopied, setAccountCopied] = useState(false);
  const [editEntry, setEditEntry] = useState<VaultEntry | null>(null);
  const [editSaving, setEditSaving] = useState(false);
  const [editForm, setEditForm] = useState({
    projectName: "",
    account: "",
    category: "",
    password: "",
    notes: "",
  });
  async function revealPassword(entry: VaultEntry) {
    setRevealingId(entry.id);
    setPasswordCopied(false);
    setAccountCopied(false);
    try {
      if (
        entry.passwordCipher === "encrypted-demo-value" ||
        entry.passwordIv === "demo-iv"
      ) {
        setRevealedSecret({
          entry,
          password: "",
          error: "这是内置演示记录，没有保存真实密码。你新建的记录可以正常解密查看。",
        });
        return;
      }

      if (entry.decryptionError) {
        throw new Error("Record decryption failed");
      }

      const password = entry.passwordCipher.startsWith(
        ENCRYPTED_RECORD_PREFIX,
      )
        ? (
            await decryptVaultRecord(
              entry.passwordCipher,
              entry.passwordIv,
              masterPassword,
            )
          ).password
        : await decryptLegacySecret(
            entry.passwordCipher,
            entry.passwordIv,
            masterPassword,
          );
      setRevealedSecret({ entry, password, error: "" });
    } catch {
      setRevealedSecret({
        entry,
        password: "",
        error: "密码解密失败。请锁定密码库后重新输入主密码再试。",
      });
    } finally {
      setRevealingId("");
    }
  }

  async function copyRevealedPassword() {
    if (!revealedSecret?.password) return;
    await navigator.clipboard.writeText(revealedSecret.password);
    setPasswordCopied(true);
  }

  async function copyRevealedAccount() {
    if (!revealedSecret?.entry.account) return;
    await navigator.clipboard.writeText(revealedSecret.entry.account);
    setAccountCopied(true);
  }

  function beginEditEntry(entry: VaultEntry) {
    setRevealedSecret(null);
    setEditEntry(entry);
    setEditForm({
      projectName: entry.projectName,
      account: entry.account,
      category: entry.category,
      password: "",
      notes: entry.notes ?? "",
    });
  }

  async function saveEditedEntry(event: FormEvent) {
    event.preventDefault();
    if (!editEntry) return;
    setEditSaving(true);
    try {
      const saved = await handleUpdateEntry(editEntry.id, editForm);
      if (saved) setEditEntry(null);
    } finally {
      setEditSaving(false);
    }
  }

  return (
    <div
      className={
        recordsOnly
          ? "vault-layout records-only"
          : "vault-layout vault-overview"
      }
    >
      <div className="vault-main">
        <section className="panel generator-panel" id="password-generator">
          <div className="section-heading">
            <div>
              <span className="eyebrow">实时生成</span>
              <h2>生成安全密码</h2>
            </div>
            <span className="strength-badge">强</span>
          </div>
          <div className="generated-row">
            <code>{generatedPassword}</code>
            <button type="button" onClick={copyGeneratedPassword}>
              复制
            </button>
            <button type="button" onClick={regenerate}>
              重新生成
            </button>
          </div>
          <div className="length-row">
            <label htmlFor="password-length">密码长度</label>
            <input
              id="password-length"
              type="range"
              min="2"
              max="30"
              value={passwordLength}
              onChange={(event) => setPasswordLength(Number(event.target.value))}
            />
            <PasswordLengthInput
              value={passwordLength}
              onChange={setPasswordLength}
            />
          </div>
          <div className="option-grid">
            {[
              ["numbers", "123", "数字"],
              ["uppercase", "A", "大写字母"],
              ["lowercase", "a", "小写字母"],
              ["symbols", "#", "特殊符号"],
            ].map(([key, icon, label]) => (
              <label className="option-card" key={key}>
                <span className="option-icon">{icon}</span>
                <span>{label}</span>
                <input
                  type="checkbox"
                  checked={passwordOptions[key]}
                  onChange={(event) =>
                    setPasswordOptions((current) => ({
                      ...current,
                      [key]: event.target.checked,
                    }))
                  }
                />
                <i className="switch" />
              </label>
            ))}
          </div>
          <div className="strength-line">
            <span>密码强度</span>
            <i />
            <strong>强</strong>
          </div>
        </section>

        <section className="panel entries-panel" id="password-records">
          <div className="section-heading entries-heading">
            <div>
              <span className="eyebrow">安全记录</span>
              <h2>已保存密码</h2>
            </div>
            <label className="search-field">
              <span>⌕</span>
              <input aria-label="搜索账号或项目" placeholder="搜索账号或项目" />
            </label>
          </div>
          <div className="entry-table">
            <div className="table-row table-head">
              <span>项目名称</span>
              <span>账号</span>
              <span>分类</span>
              <span>安全状态</span>
              <span>更新时间</span>
              <span>操作</span>
            </div>
            {vault.entries.map((entry) => (
              <div className="table-row" key={entry.id}>
                <span className="project-cell">
                  <i>{entry.projectName.slice(0, 1).toUpperCase()}</i>
                  {entry.projectName}
                </span>
                <span className="muted-account" data-label="账号">
                  {entry.account}
                </span>
                <span className="category-cell" data-label="分类">
                  <em
                    className={`category-chip ${
                      categoryTone[entry.category] ?? "blue"
                    }`}
                  >
                    {entry.category}
                  </em>
                </span>
                <span className="safe-state" data-label="安全状态">
                  ◇ {entry.securityStatus}
                </span>
                <span className="date-cell" data-label="更新时间">
                  {entry.updatedAt}
                </span>
                <span className="row-actions">
                  <button
                    type="button"
                    className="row-menu"
                    aria-label={`查看 ${entry.projectName} 的密码`}
                    disabled={revealingId === entry.id}
                    onClick={() => revealPassword(entry)}
                  >
                    {revealingId === entry.id ? "解密中…" : "查看"}
                  </button>
                  <button
                    type="button"
                    className="edit-entry"
                    aria-label={`修改 ${entry.projectName}`}
                    onClick={() => beginEditEntry(entry)}
                  >
                    修改
                  </button>
                </span>
              </div>
            ))}
          </div>
          <div className="table-footer">
            <span>共 {vault.entries.length} 条记录</span>
            <span>项目、账号、分类、备注和密码均以密文保存</span>
          </div>
        </section>
      </div>

      <aside className="panel add-entry-panel">
        <div className="section-heading">
          <div>
            <span className="eyebrow">新建记录</span>
            <h2>新增密码</h2>
          </div>
          <span className="panel-plus">＋</span>
        </div>
        <form onSubmit={handleAddEntry} className="entry-form">
          <label>
            项目名称
            <input
              value={entryForm.projectName}
              onChange={(event) =>
                setEntryForm((current) => ({
                  ...current,
                  projectName: event.target.value,
                }))
              }
              placeholder="例如：GitHub"
            />
          </label>
          <label>
            账号
            <input
              value={entryForm.account}
              onChange={(event) =>
                setEntryForm((current) => ({
                  ...current,
                  account: event.target.value,
                }))
              }
              placeholder="输入账号或邮箱"
            />
          </label>
          <label>
            密码
            <input
              type="password"
              value={entryForm.password}
              onChange={(event) =>
                setEntryForm((current) => ({
                  ...current,
                  password: event.target.value,
                }))
              }
              placeholder="输入或粘贴密码"
            />
          </label>
          <button
            type="button"
            className="use-generated"
            onClick={() =>
              setEntryForm((current) => ({
                ...current,
                password: generatedPassword,
              }))
            }
          >
            使用刚生成的密码
          </button>
          <label className="category-field">
            分类
            <input
              type="text"
              autoComplete="off"
              value={entryForm.category}
              onChange={(event) =>
                setEntryForm((current) => ({
                  ...current,
                  category: event.target.value,
                }))
              }
              placeholder="选择推荐分类或输入自定义分类"
            />
          </label>
          <div className="category-suggestions" aria-label="推荐分类">
            <span>推荐</span>
            {recommendedCategories.map((category) => (
              <button
                key={category}
                type="button"
                className={entryForm.category === category ? "active" : ""}
                onClick={() =>
                  setEntryForm((current) => ({ ...current, category }))
                }
              >
                {category}
              </button>
            ))}
          </div>
          <label>
            备注
            <textarea
              value={entryForm.notes}
              onChange={(event) =>
                setEntryForm((current) => ({
                  ...current,
                  notes: event.target.value,
                }))
              }
              placeholder="添加备注（可选）"
              rows={4}
            />
          </label>
          <button className="primary-button save-entry" type="submit">
            保存密码
          </button>
        </form>
      </aside>

      {revealedSecret ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="password-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="password-view-title"
          >
            <div className="section-heading">
              <div>
                <span className="eyebrow">本地解密</span>
                <h2 id="password-view-title">
                  {revealedSecret.entry.projectName}
                </h2>
              </div>
              <button
                type="button"
                className="modal-close"
                aria-label="关闭密码查看窗口"
                onClick={() => setRevealedSecret(null)}
              >
                ×
              </button>
            </div>
            <div className="secret-credentials">
              <div className="secret-account">
                <span>账号</span>
                <div>
                  <strong>{revealedSecret.entry.account}</strong>
                  <button type="button" onClick={copyRevealedAccount}>
                    {accountCopied ? "已复制" : "复制账号"}
                  </button>
                </div>
              </div>
              {revealedSecret.error ? (
                <p className="secret-error">{revealedSecret.error}</p>
              ) : (
                <div className="secret-password">
                  <span className="secret-label">密码</span>
                  <div className="secret-display">
                    <code>{revealedSecret.password}</code>
                    <button type="button" onClick={copyRevealedPassword}>
                      {passwordCopied ? "已复制" : "复制密码"}
                    </button>
                  </div>
                  <p className="secret-note">
                    密码仅在当前已解锁的浏览器中解密，不会以明文发送到服务端。
                  </p>
                </div>
              )}
            </div>
            <div className="secret-notes">
              <span>备注</span>
              <p>{revealedSecret.entry.notes || "暂无备注"}</p>
            </div>
            <button
              className="secondary-button password-modal-done"
              type="button"
              onClick={() => setRevealedSecret(null)}
            >
              完成
            </button>
          </section>
        </div>
      ) : null}

      {editEntry ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="password-modal edit-entry-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="edit-entry-title"
          >
            <div className="section-heading">
              <div>
                <span className="eyebrow">编辑记录</span>
                <h2 id="edit-entry-title">修改密码项目</h2>
              </div>
              <button
                type="button"
                className="modal-close"
                aria-label="关闭修改窗口"
                onClick={() => setEditEntry(null)}
              >
                ×
              </button>
            </div>
            <form className="edit-entry-form" onSubmit={saveEditedEntry}>
              <label>
                项目名称
                <input
                  autoFocus
                  value={editForm.projectName}
                  onChange={(event) =>
                    setEditForm((current) => ({
                      ...current,
                      projectName: event.target.value,
                    }))
                  }
                />
              </label>
              <label>
                账号
                <input
                  value={editForm.account}
                  onChange={(event) =>
                    setEditForm((current) => ({
                      ...current,
                      account: event.target.value,
                    }))
                  }
                />
              </label>
              <label>
                分类
                <input
                  type="text"
                  autoComplete="off"
                  value={editForm.category}
                  onChange={(event) =>
                    setEditForm((current) => ({
                      ...current,
                      category: event.target.value,
                    }))
                  }
                />
              </label>
              <div className="category-suggestions" aria-label="推荐分类">
                <span>推荐</span>
                {recommendedCategories.map((category) => (
                  <button
                    key={category}
                    type="button"
                    className={editForm.category === category ? "active" : ""}
                    onClick={() =>
                      setEditForm((current) => ({ ...current, category }))
                    }
                  >
                    {category}
                  </button>
                ))}
              </div>
              <label>
                新密码
                <input
                  type="password"
                  autoComplete="new-password"
                  value={editForm.password}
                  onChange={(event) =>
                    setEditForm((current) => ({
                      ...current,
                      password: event.target.value,
                    }))
                  }
                  placeholder="留空则保持原密码不变"
                />
                <span className="optional-field-note">
                  不填写新密码时会保留原密码，其他内容仍会重新加密保存。
                </span>
              </label>
              <label>
                备注
                <textarea
                  rows={4}
                  value={editForm.notes}
                  onChange={(event) =>
                    setEditForm((current) => ({
                      ...current,
                      notes: event.target.value,
                    }))
                  }
                  placeholder="添加备注（可选）"
                />
              </label>
              <div className="modal-actions">
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => setEditEntry(null)}
                >
                  取消
                </button>
                <button
                  className="primary-button"
                  type="submit"
                  disabled={editSaving}
                >
                  {editSaving ? "保存中…" : "保存修改"}
                </button>
              </div>
            </form>
          </section>
        </div>
      ) : null}
    </div>
  );
}

function ForcedPasswordChangeView({
  handleChangeMasterPassword,
}: {
  handleChangeMasterPassword: MasterPasswordChangeHandler;
}) {
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [changingPassword, setChangingPassword] = useState(false);
  const [passwordChangeError, setPasswordChangeError] = useState("");

  async function submitPasswordChange(event: FormEvent) {
    event.preventDefault();
    const { currentPassword, newPassword, confirmPassword } = passwordForm;
    const validationError = validateMasterPasswordChange(
      currentPassword,
      newPassword,
      confirmPassword,
    );
    if (validationError) {
      setPasswordChangeError(validationError);
      return;
    }

    setPasswordChangeError("");
    setChangingPassword(true);
    const result = await handleChangeMasterPassword(
      currentPassword,
      newPassword,
    );
    if (!result.ok) {
      setPasswordChangeError(result.error ?? "主密码修改失败");
    }
    setChangingPassword(false);
  }

  return (
    <div className="settings-layout forced-password-layout">
      <section className="panel forced-password-intro">
        <div className="forced-password-icon" aria-hidden="true">
          !
        </div>
        <div>
          <span className="eyebrow">首次使用安全检查</span>
          <h2>请先修改默认主密码</h2>
          <p>
            默认密码仅用于第一次进入。在设置新的主密码前，密码库、密码记录及其他设置均不可访问。
          </p>
        </div>
      </section>

      <section className="panel settings-panel password-change-panel forced">
        <div className="section-heading">
          <div>
            <span className="eyebrow">必须完成</span>
            <h2>设置你的主密码</h2>
          </div>
          <span className="policy-status">整库重新加密</span>
        </div>
        <form
          className="password-change-form"
          onSubmit={submitPasswordChange}
        >
          <label className="current-password-field">
            当前默认密码
            <input
              type="password"
              autoComplete="current-password"
              value={passwordForm.currentPassword}
              onChange={(event) =>
                setPasswordForm((current) => ({
                  ...current,
                  currentPassword: event.target.value,
                }))
              }
              placeholder="输入默认密码 12345678"
              disabled={changingPassword}
              autoFocus
            />
          </label>
          <div className="password-change-grid">
            <label>
              新主密码
              <input
                type="password"
                autoComplete="new-password"
                minLength={10}
                maxLength={128}
                value={passwordForm.newPassword}
                onChange={(event) =>
                  setPasswordForm((current) => ({
                    ...current,
                    newPassword: event.target.value,
                  }))
                }
                placeholder="输入 10–128 位新主密码"
                disabled={changingPassword}
              />
            </label>
            <label>
              确认新主密码
              <input
                type="password"
                autoComplete="new-password"
                minLength={10}
                maxLength={128}
                value={passwordForm.confirmPassword}
                onChange={(event) =>
                  setPasswordForm((current) => ({
                    ...current,
                    confirmPassword: event.target.value,
                  }))
                }
                placeholder="再次输入新主密码"
                disabled={changingPassword}
              />
            </label>
          </div>
          <div className="password-change-footer">
            <p>
              新主密码至少包含大写字母、小写字母、数字和符号中的三类。
            </p>
            <button
              className="primary-button"
              type="submit"
              disabled={changingPassword}
            >
              {changingPassword ? "正在安全更新…" : "修改密码并重新登录"}
            </button>
          </div>
          {passwordChangeError ? (
            <p className="form-error" role="alert">
              {passwordChangeError}
            </p>
          ) : null}
        </form>
        <div className="security-callout password-change-callout">
          <ShieldMark small />
          <p>
            修改成功后，默认密码立即失效，所有设备都必须使用新主密码重新登录。
          </p>
        </div>
      </section>
    </div>
  );
}

function SettingsView({
  vault,
  deviceId,
  theme,
  setTheme,
  masterPassword,
  handleImportEncryptedEntries,
  handleChangeMasterPassword,
  handleToggleTwoFactor,
  handleLockoutPolicy,
  handleSaveRecoveryEmail,
  handleSaveSmtpConfig,
  handleToggleSmtpFeature,
  handleTestSmtp,
  setDeleteTarget,
}: {
  vault: VaultPayload;
  deviceId: string;
  theme: ThemePreference;
  setTheme: (theme: ThemePreference) => void;
  masterPassword: string;
  handleImportEncryptedEntries: (
    entries: ImportableEncryptedEntry[],
  ) => Promise<number>;
  handleChangeMasterPassword: MasterPasswordChangeHandler;
  handleToggleTwoFactor: () => void;
  handleLockoutPolicy: (
    maxFailedAttempts: number,
    lockoutMinutes: number,
  ) => void;
  handleSaveRecoveryEmail: (email: string) => Promise<boolean>;
  handleSaveSmtpConfig: (config: {
    provider: string;
    host: string;
    port: number;
    security: string;
    username: string;
    secret: string;
    fromName: string;
  }) => Promise<boolean>;
  handleToggleSmtpFeature: () => Promise<void>;
  handleTestSmtp: () => Promise<boolean>;
  setDeleteTarget: (device: TrustedDevice) => void;
}) {
  const [notificationEmail, setNotificationEmail] = useState(
    isNotificationEmailConfigured(vault.settings.email)
      ? vault.settings.email
      : "",
  );
  const [savingEmail, setSavingEmail] = useState(false);
  const [smtpProvider, setSmtpProvider] = useState(
    displaySmtpProvider(vault.settings.smtpProvider) || "QQ 邮箱",
  );
  const [smtpHost, setSmtpHost] = useState(
    vault.settings.smtpHost || "smtp.qq.com",
  );
  const [smtpPort, setSmtpPort] = useState(vault.settings.smtpPort || 465);
  const [smtpSecurity, setSmtpSecurity] = useState(
    vault.settings.smtpSecurity || "tls",
  );
  const [smtpUsername, setSmtpUsername] = useState(
    vault.settings.smtpUsername,
  );
  const [smtpSecret, setSmtpSecret] = useState("");
  const [smtpFromName, setSmtpFromName] = useState(
    vault.settings.smtpFromName || "钥密",
  );
  const [savingSmtp, setSavingSmtp] = useState(false);
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [changingPassword, setChangingPassword] = useState(false);
  const [passwordChangeError, setPasswordChangeError] = useState("");
  const [transferBusy, setTransferBusy] = useState(false);
  const [transferStatus, setTransferStatus] = useState("");

  useEffect(() => {
    setNotificationEmail(
      isNotificationEmailConfigured(vault.settings.email)
        ? vault.settings.email
        : "",
    );
  }, [vault.settings.email]);

  useEffect(() => {
    setSmtpProvider(
      displaySmtpProvider(vault.settings.smtpProvider) || "QQ 邮箱",
    );
    setSmtpHost(vault.settings.smtpHost || "smtp.qq.com");
    setSmtpPort(vault.settings.smtpPort || 465);
    setSmtpSecurity(vault.settings.smtpSecurity || "tls");
    setSmtpUsername(vault.settings.smtpUsername);
    setSmtpFromName(vault.settings.smtpFromName || "钥密");
    setSmtpSecret("");
  }, [
    vault.settings.smtpProvider,
    vault.settings.smtpHost,
    vault.settings.smtpPort,
    vault.settings.smtpSecurity,
    vault.settings.smtpUsername,
    vault.settings.smtpFromName,
  ]);

  async function saveNotificationEmail(event: FormEvent) {
    event.preventDefault();
    setSavingEmail(true);
    await handleSaveRecoveryEmail(notificationEmail);
    setSavingEmail(false);
  }

  async function saveSmtpConfig(event: FormEvent) {
    event.preventDefault();
    setSavingSmtp(true);
    const saved = await handleSaveSmtpConfig({
      provider: smtpProvider,
      host: smtpHost.trim(),
      port: smtpPort,
      security: smtpSecurity,
      username: smtpUsername.trim(),
      secret: smtpSecret.trim(),
      fromName: smtpFromName.trim(),
    });
    if (saved) setSmtpSecret("");
    setSavingSmtp(false);
  }

  async function testSmtp() {
    setTestingSmtp(true);
    await handleTestSmtp();
    setTestingSmtp(false);
  }

  async function exportEncryptedBackup() {
    if (transferBusy) return;
    setTransferBusy(true);
    setTransferStatus("正在创建加密备份…");
    try {
      const { backup, skipped } = await createEncryptedBackup(
        vault.entries,
        masterPassword,
      );
      const date = new Date().toISOString().slice(0, 10);
      downloadEncryptedBackup(backup, `yuemi-vault-${date}.yuemi`);
      setTransferStatus(
        `已导出 ${backup.recordCount} 条加密记录${
          skipped ? `，跳过 ${skipped} 条内置演示或旧格式记录` : ""
        }`,
      );
    } catch (error) {
      setTransferStatus(
        error instanceof Error ? error.message : "加密备份导出失败",
      );
    } finally {
      setTransferBusy(false);
    }
  }

  async function importBrowserPasswords(
    event: React.ChangeEvent<HTMLInputElement>,
  ) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || transferBusy) return;
    if (file.size > 5 * 1024 * 1024) {
      setTransferStatus("CSV 文件不能超过 5 MB");
      return;
    }

    setTransferBusy(true);
    setTransferStatus("正在本地解析并加密浏览器密码…");
    try {
      const records = parseBrowserPasswordCsv(await file.text());
      const encrypted = await encryptVaultRecordsBatch(
        records,
        masterPassword,
      );
      const imported = await handleImportEncryptedEntries(encrypted);
      setTransferStatus(
        `已从 Chrome / Edge 安全导入 ${imported} 条记录；原 CSV 请及时删除`,
      );
    } catch (error) {
      setTransferStatus(
        error instanceof Error ? error.message : "浏览器密码导入失败",
      );
    } finally {
      setTransferBusy(false);
    }
  }

  async function importEncryptedBackup(
    event: React.ChangeEvent<HTMLInputElement>,
  ) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || transferBusy) return;
    if (file.size > 20 * 1024 * 1024) {
      setTransferStatus("加密备份文件不能超过 20 MB");
      return;
    }

    setTransferBusy(true);
    setTransferStatus("正在本地验证并解密备份…");
    try {
      const records = await decryptEncryptedBackup(
        await file.text(),
        masterPassword,
      );
      const imported = await handleImportEncryptedEntries(records);
      setTransferStatus(`已从加密备份恢复 ${imported} 条密码记录`);
    } catch (error) {
      setTransferStatus(
        error instanceof Error ? error.message : "加密备份导入失败",
      );
    } finally {
      setTransferBusy(false);
    }
  }

  async function changeMasterPassword(event: FormEvent) {
    event.preventDefault();
    const { currentPassword, newPassword, confirmPassword } = passwordForm;
    const validationError = validateMasterPasswordChange(
      currentPassword,
      newPassword,
      confirmPassword,
    );
    if (validationError) {
      setPasswordChangeError(validationError);
      return;
    }

    setPasswordChangeError("");
    setChangingPassword(true);
    const result = await handleChangeMasterPassword(
      currentPassword,
      newPassword,
    );
    if (!result.ok) {
      setPasswordChangeError(result.error ?? "主密码修改失败");
    }
    setChangingPassword(false);
  }

  function updateSmtpProvider(provider: string) {
    setSmtpProvider(provider);
    const preset = findSmtpPreset(provider);
    if (preset) {
      setSmtpHost(preset.host);
      setSmtpPort(preset.port);
      setSmtpSecurity(preset.security);
    }
  }

  return (
    <div className="settings-layout">
      <section className="panel settings-panel theme-panel">
        <div className="section-heading">
          <div>
            <span className="eyebrow">个性化</span>
            <h2>界面主题</h2>
          </div>
          <span className="theme-device-note">仅保存在当前设备</span>
        </div>
        <p className="settings-description">
          选择更舒适的显示方式；使用“跟随系统”时，会自动匹配设备的深浅色设置。
        </p>
        <div
          className="theme-options"
          role="radiogroup"
          aria-label="界面主题"
        >
          {themeOptions.map((option) => (
            <button
              className={
                theme === option.value ? "theme-option active" : "theme-option"
              }
              type="button"
              role="radio"
              aria-checked={theme === option.value}
              key={option.value}
              onClick={() => setTheme(option.value)}
            >
              <span
                className={`theme-preview theme-preview-${option.value}`}
                aria-hidden="true"
              >
                <i />
                <b />
                <em />
              </span>
              <span className="theme-option-copy">
                <strong>{option.label}</strong>
                <small>{option.description}</small>
              </span>
              <span className="theme-check" aria-hidden="true">
                {theme === option.value ? "✓" : ""}
              </span>
            </button>
          ))}
        </div>
      </section>

      <section
        className="panel transfer-panel"
        aria-labelledby="vault-transfer-title"
      >
        <div className="section-heading transfer-heading">
          <div>
            <span className="eyebrow">导入与备份</span>
            <h2 id="vault-transfer-title">迁移密码本</h2>
          </div>
          <span className="policy-status">本地加密处理</span>
        </div>
        <p className="settings-description">
          支持 Chrome、Edge 导出的 CSV，以及钥密专用加密备份。浏览器
          CSV 会先在当前设备加密，再上传密文。
        </p>
        <div className="transfer-actions">
          <label
            className={
              transferBusy ? "transfer-button disabled" : "transfer-button"
            }
          >
            <span aria-hidden="true">⇩</span>
            导入 Chrome / Edge
            <input
              type="file"
              accept=".csv,text/csv"
              disabled={transferBusy}
              onChange={importBrowserPasswords}
            />
          </label>
          <label
            className={
              transferBusy ? "transfer-button disabled" : "transfer-button"
            }
          >
            <span aria-hidden="true">↺</span>
            导入加密备份
            <input
              type="file"
              accept=".yuemi,application/json"
              disabled={transferBusy}
              onChange={importEncryptedBackup}
            />
          </label>
          <button
            className="transfer-button primary"
            type="button"
            disabled={transferBusy}
            onClick={() => void exportEncryptedBackup()}
          >
            <span aria-hidden="true">⇧</span>
            导出加密备份
          </button>
        </div>
        <div className="transfer-security-note">
          <ShieldMark small />
          <p>
            备份文件使用主密码通过 PBKDF2 和 AES-GCM
            加密，恢复时必须输入同一个主密码。Chrome / Edge
            导出的原始 CSV 是明文文件，导入后请及时删除。
          </p>
        </div>
        {transferStatus ? (
          <p className="transfer-status" role="status" aria-live="polite">
            {transferBusy ? <i aria-hidden="true" /> : <span>✓</span>}
            {transferStatus}
          </p>
        ) : null}
      </section>

      <section className="panel settings-panel">
        <div className="section-heading">
          <div>
            <span className="eyebrow">登录保护</span>
            <h2>新设备二次验证</h2>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={vault.settings.twoFactorEnabled}
            className={
              vault.settings.twoFactorEnabled
                ? "large-switch enabled"
                : "large-switch"
            }
            onClick={() => {
              const needsEmail =
                !vault.settings.twoFactorEnabled &&
                !isNotificationEmailConfigured(vault.settings.email);
              const needsSmtp =
                !vault.settings.twoFactorEnabled &&
                !vault.settings.smtpEnabled;
              void handleToggleTwoFactor();
              if (needsEmail) {
                window.requestAnimationFrame(() => {
                  document.getElementById("notification-email")?.focus();
                });
              } else if (needsSmtp) {
                window.requestAnimationFrame(() => {
                  document.getElementById("smtp-feature-switch")?.focus();
                });
              }
            }}
          >
            <i />
            <span className="sr-only">切换新设备二次验证</span>
          </button>
        </div>
        <p className="settings-description">
          所有设备每次进入都会由服务端重新校验主密码；开启后，新设备还需要邮箱验证码确认身份。
        </p>
        <div className="login-protection-email-heading">
          <div>
            <strong>通知邮箱</strong>
            <span>用于新设备验证和主密码找回</span>
          </div>
          <span
            className={
              isNotificationEmailConfigured(vault.settings.email)
                ? "policy-status"
                : "policy-status inactive"
            }
          >
            {isNotificationEmailConfigured(vault.settings.email)
              ? "✓ 已设置"
              : "启用前请先填写"}
          </span>
        </div>
        <form
          className="recovery-email-form"
          onSubmit={saveNotificationEmail}
        >
          <label htmlFor="notification-email">通知邮箱</label>
          <div>
            <input
              id="notification-email"
              type="email"
              autoComplete="email"
              value={notificationEmail}
              onChange={(event) => setNotificationEmail(event.target.value)}
              placeholder="例如：name@example.com"
            />
            <button
              className="primary-button"
              type="submit"
              disabled={savingEmail}
            >
              {savingEmail
                ? "保存中…"
                : notificationEmail.trim()
                  ? "保存邮箱"
                  : "移除邮箱"}
            </button>
          </div>
        </form>
        <div className="security-callout">
          <ShieldMark small />
          <p>
            保存有效邮箱后即可修改上方开关，登录页也会出现“忘记主密码”。清空并保存会同时关闭这两项保护。
          </p>
        </div>
      </section>

      <section className="panel settings-panel password-change-panel">
        <div className="section-heading">
          <div>
            <span className="eyebrow">身份凭证</span>
            <h2>修改主密码</h2>
          </div>
          <span className="policy-status">整库重新加密</span>
        </div>
        <p className="settings-description">
          输入当前主密码进行验证。现有密码记录会在本机解密，再使用新主密码重新加密后提交。
        </p>
        <form className="password-change-form" onSubmit={changeMasterPassword}>
          <label className="current-password-field">
            当前主密码
            <input
              type="password"
              autoComplete="current-password"
              value={passwordForm.currentPassword}
              onChange={(event) =>
                setPasswordForm((current) => ({
                  ...current,
                  currentPassword: event.target.value,
                }))
              }
              placeholder="输入当前主密码"
              disabled={changingPassword}
            />
          </label>
          <div className="password-change-grid">
            <label>
              新主密码
              <input
                type="password"
                autoComplete="new-password"
                minLength={10}
                maxLength={128}
                value={passwordForm.newPassword}
                onChange={(event) =>
                  setPasswordForm((current) => ({
                    ...current,
                    newPassword: event.target.value,
                  }))
                }
                placeholder="输入 10–128 位新主密码"
                disabled={changingPassword}
              />
            </label>
            <label>
              确认新主密码
              <input
                type="password"
                autoComplete="new-password"
                minLength={10}
                maxLength={128}
                value={passwordForm.confirmPassword}
                onChange={(event) =>
                  setPasswordForm((current) => ({
                    ...current,
                    confirmPassword: event.target.value,
                  }))
                }
                placeholder="再次输入新主密码"
                disabled={changingPassword}
              />
            </label>
          </div>
          <div className="password-change-footer">
            <p>
              至少包含大写字母、小写字母、数字和符号中的三类。修改后所有设备都需要重新登录。
            </p>
            <button
              className="primary-button"
              type="submit"
              disabled={changingPassword}
            >
              {changingPassword ? "正在重新加密…" : "确认修改主密码"}
            </button>
          </div>
          {passwordChangeError ? (
            <p className="form-error" role="alert">
              {passwordChangeError}
            </p>
          ) : null}
        </form>
        <div className="security-callout password-change-callout">
          <ShieldMark small />
          <p>
            服务器只保存新主密码的校验哈希，不保存明文。此前导出的加密备份仍需使用导出时的旧主密码恢复。
          </p>
        </div>
      </section>

      <section className="panel settings-panel smtp-panel">
        <div className="section-heading">
          <div>
            <span className="eyebrow">邮件发送</span>
            <h2>SMTP 邮件服务</h2>
          </div>
          <div className="smtp-header-actions">
            {vault.settings.smtpFeatureEnabled ? (
              <span
                className={
                  vault.settings.smtpEnabled
                    ? "policy-status"
                    : "policy-status inactive"
                }
              >
                {vault.settings.smtpEnabled
                  ? "✓ 已测试可用"
                  : vault.settings.hasSmtpSecret
                    ? "等待测试"
                    : "尚未配置"}
              </span>
            ) : null}
            <button
              id="smtp-feature-switch"
              type="button"
              role="switch"
              aria-label="启用 SMTP 邮件服务"
              aria-checked={vault.settings.smtpFeatureEnabled}
              className={
                vault.settings.smtpFeatureEnabled
                  ? "large-switch enabled"
                  : "large-switch"
              }
              onClick={() => void handleToggleSmtpFeature()}
            >
              <i />
            </button>
          </div>
        </div>
        {vault.settings.smtpFeatureEnabled ? (
          <>
            <p className="settings-description">
              支持任意公网 SMTP 邮箱服务。QQ、163、Gmail
              仅提供快捷预设，也可以直接填写其他服务商的服务器参数。授权码会在服务器端加密保存。
            </p>
            <form className="smtp-config-form" onSubmit={saveSmtpConfig}>
              <div className="smtp-form-grid">
                <label>
                  邮箱服务商
                  <input
                    id="smtp-provider"
                    list="smtp-provider-options"
                    type="text"
                    value={smtpProvider}
                    onChange={(event) =>
                      updateSmtpProvider(event.target.value)
                    }
                    placeholder="例如：企业邮箱"
                    maxLength={50}
                  />
                  <datalist id="smtp-provider-options">
                    {smtpPresetOptions.map((preset) => (
                      <option key={preset.label} value={preset.label} />
                    ))}
                  </datalist>
                </label>
                <label>
                  SMTP 服务器
                  <input
                    type="text"
                    inputMode="url"
                    autoCapitalize="none"
                    spellCheck={false}
                    value={smtpHost}
                    onChange={(event) => setSmtpHost(event.target.value)}
                    placeholder="smtp.example.com"
                  />
                </label>
                <label>
                  端口
                  <input
                    type="number"
                    inputMode="numeric"
                    min={1}
                    max={65535}
                    value={smtpPort}
                    onChange={(event) =>
                      setSmtpPort(Number(event.target.value))
                    }
                  />
                </label>
                <label>
                  加密方式
                  <select
                    value={smtpSecurity}
                    onChange={(event) =>
                      setSmtpSecurity(event.target.value)
                    }
                  >
                    <option value="tls">SSL/TLS</option>
                    <option value="starttls">STARTTLS</option>
                  </select>
                </label>
                <label>
                  发件账号
                  <input
                    type="email"
                    autoComplete="username"
                    value={smtpUsername}
                    onChange={(event) =>
                      setSmtpUsername(event.target.value)
                    }
                    placeholder="name@example.com"
                  />
                </label>
                <label>
                  发件名称
                  <input
                    type="text"
                    value={smtpFromName}
                    onChange={(event) =>
                      setSmtpFromName(event.target.value)
                    }
                    maxLength={40}
                    placeholder="钥密"
                  />
                </label>
                <label className="smtp-secret-field">
                  SMTP 授权码 / 应用专用密码
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={smtpSecret}
                    onChange={(event) => setSmtpSecret(event.target.value)}
                    placeholder={
                      vault.settings.hasSmtpSecret
                        ? "已安全保存，连接参数不变时可留空"
                        : "输入授权码或应用专用密码"
                    }
                  />
                </label>
              </div>
              <p className="smtp-help">
                请填写邮箱服务商提供的 SMTP 授权码或应用专用密码，不要填写邮箱登录密码。端口
                25 在当前部署环境不可用。
              </p>
              <div className="smtp-actions">
                <button
                  className="secondary-button"
                  type="submit"
                  disabled={savingSmtp || testingSmtp}
                >
                  {savingSmtp ? "保存中…" : "保存 SMTP 配置"}
                </button>
                <button
                  className="primary-button"
                  type="button"
                  onClick={() => void testSmtp()}
                  disabled={
                    testingSmtp ||
                    savingSmtp ||
                    !vault.settings.hasSmtpSecret ||
                    !isNotificationEmailConfigured(vault.settings.email)
                  }
                >
                  {testingSmtp ? "发送中…" : "发送测试邮件"}
                </button>
              </div>
              {!isNotificationEmailConfigured(vault.settings.email) ? (
                <p className="form-error">
                  请先在上方保存通知邮箱，测试邮件会发送到该邮箱。
                </p>
              ) : null}
            </form>
          </>
        ) : null}
      </section>

      <section className="panel settings-panel lockout-panel">
        <div className="section-heading">
          <div>
            <span className="eyebrow">防暴力破解</span>
            <h2>密码错误锁定策略</h2>
          </div>
          <span className="policy-status">服务端强制执行</span>
        </div>
        <p className="settings-description">
          同一设备连续输错达到设定次数后，将在设定时间内无法再次访问；刷新页面也不会解除锁定。
        </p>
        <div className="lockout-policy-grid">
          <label>
            允许错误次数
            <select
              aria-label="允许错误次数"
              value={vault.settings.maxFailedAttempts}
              onChange={(event) =>
                handleLockoutPolicy(
                  Number(event.target.value),
                  vault.settings.lockoutMinutes,
                )
              }
            >
              <option value="2">2 次</option>
              <option value="3">3 次</option>
              <option value="5">5 次</option>
              <option value="8">8 次</option>
              <option value="10">10 次</option>
            </select>
          </label>
          <label>
            锁定时长
            <select
              aria-label="密码错误锁定时长"
              value={vault.settings.lockoutMinutes}
              onChange={(event) =>
                handleLockoutPolicy(
                  vault.settings.maxFailedAttempts,
                  Number(event.target.value),
                )
              }
            >
              <option value="1">1 分钟</option>
              <option value="5">5 分钟</option>
              <option value="15">15 分钟</option>
              <option value="30">30 分钟</option>
              <option value="60">1 小时</option>
              <option value="1440">24 小时</option>
            </select>
          </label>
        </div>
        <div className="policy-summary">
          当前策略：连续输错
          <strong>{vault.settings.maxFailedAttempts} 次</strong>
          后锁定
          <strong>{vault.settings.lockoutMinutes} 分钟</strong>
        </div>
      </section>

      <section className="panel devices-panel">
        <div className="section-heading">
          <div>
            <span className="eyebrow">设备管理</span>
            <h2>已加入的设备</h2>
          </div>
          <span className="device-count">{vault.devices.length} 台设备</span>
        </div>
        <p className="settings-description">
          删除设备后，该设备下次进入时必须重新完成邮箱验证。
        </p>
        <div className="device-list">
          {vault.devices.map((device) => {
            const isCurrent = device.id === deviceId;
            return (
              <article className="device-card" key={device.id}>
                <div className="device-icon" aria-hidden="true">
                  ▣
                </div>
                <div className="device-details">
                  <div>
                    <h3>{device.deviceName}</h3>
                    {isCurrent ? <em>当前设备</em> : null}
                  </div>
                  <p>
                    {device.browser} · {device.location}
                  </p>
                  <span>最近活动：{device.lastActive}</span>
                </div>
                <button
                  className="delete-device"
                  data-testid={`delete-device-${device.id}`}
                  type="button"
                  onClick={() => setDeleteTarget(device)}
                >
                  删除设备
                </button>
              </article>
            );
          })}
        </div>
      </section>

      <section className="panel danger-zone">
        <div>
          <span className="eyebrow">高级安全</span>
          <h2>自动锁定</h2>
          <p>连续 15 分钟无操作后自动锁定密码库。</p>
        </div>
        <select aria-label="自动锁定时间" defaultValue="15">
          <option value="5">5 分钟</option>
          <option value="15">15 分钟</option>
          <option value="30">30 分钟</option>
          <option value="60">1 小时</option>
        </select>
      </section>
    </div>
  );
}
