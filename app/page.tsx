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
  };
};

const DEMO_CODE = "246810";
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
  },
};

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

export default function Home() {
  const [phase, setPhase] = useState<Phase>("locked");
  const [view, setView] = useState<AppView>("vault");
  const [vault, setVault] = useState<VaultPayload>(defaultPayload);
  const [masterPassword, setMasterPassword] = useState("");
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
  const [recoveryStep, setRecoveryStep] =
    useState<RecoveryStep>("closed");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [recoveryEmail, setRecoveryEmail] = useState("");
  const [recoveryToken, setRecoveryToken] = useState("");
  const [recoveryError, setRecoveryError] = useState("");
  const [recoveredPassword, setRecoveredPassword] = useState("");

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
          unlockPassword,
        );
        setVault({ ...payload, entries });
      } catch {
        setToast("暂时无法读取密码库，请稍后重试");
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
      };
      setRecoveryAvailable(Boolean(result.configured));
      setRecoveryMaskedEmail(result.maskedEmail ?? "");
    } catch {
      setRecoveryAvailable(false);
      setRecoveryMaskedEmail("");
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
      await fetchVault(result.sessionToken, masterPassword);
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
      await fetchVault(result.sessionToken, masterPassword);
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

  async function handleToggleTwoFactor() {
    if (
      !vault.settings.twoFactorEnabled &&
      !isNotificationEmailConfigured(vault.settings.email)
    ) {
      setToast("请先在登录保护中保存通知邮箱");
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

  function openRecovery() {
    setRecoveryCode("");
    setRecoveryEmail("");
    setRecoveryToken("");
    setRecoveryError("");
    setRecoveredPassword("");
    setRecoveryStep("code");
  }

  function closeRecovery() {
    setRecoveryStep("closed");
    setRecoveryCode("");
    setRecoveryEmail("");
    setRecoveryToken("");
    setRecoveryError("");
    setRecoveredPassword("");
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
        demoPassword?: string;
      };
      if (!response.ok || !result.delivered) {
        setRecoveryError(result.error ?? "通知邮箱验证失败");
        return;
      }
      setRecoveredPassword(result.demoPassword ?? "");
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
                type="password"
                autoComplete="current-password"
                value={masterPassword}
                onChange={(event) => setMasterPassword(event.target.value)}
                placeholder="输入主密码"
              />
              <span aria-hidden="true">◉</span>
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
          <div className="demo-hint">
            <span>演示主密码</span>
            <strong>KeySafe2026!</strong>
          </div>
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
                  <span className="recovery-step">演示发送完成</span>
                  <h2 id="recovery-title">新主密码已发送</h2>
                  <p>
                    通知邮箱验证成功。正式邮件服务接入前，演示主密码显示如下。
                  </p>
                  <div className="demo-hint recovery-password">
                    <span>新主密码</span>
                    <strong>{recoveredPassword}</strong>
                  </div>
                  <button
                    className="primary-button"
                    type="button"
                    onClick={() => {
                      setMasterPassword(recoveredPassword);
                      closeRecovery();
                    }}
                  >
                    返回登录并填写密码
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

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup sidebar-brand">
          <ShieldMark />
          <span>钥密</span>
        </div>
        <nav aria-label="主要导航">
          <button
            className={view === "vault" ? "nav-item active" : "nav-item"}
            onClick={() => setView("vault")}
          >
            <span>▣</span>密码库
          </button>
          <button
            className={view === "records" ? "nav-item active" : "nav-item"}
            onClick={() => setView("records")}
          >
            <span>▤</span>密码记录
          </button>
          <button
            className={view === "settings" ? "nav-item active" : "nav-item"}
            onClick={() => setView("settings")}
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
              {view === "settings"
                ? "设置 / 安全"
                : view === "records"
                  ? "安全记录"
                  : "个人密码空间"}
            </span>
            <h1>
              {view === "settings"
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

        {view !== "settings" ? (
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
            handleToggleTwoFactor={handleToggleTwoFactor}
            handleLockoutPolicy={handleLockoutPolicy}
            handleSaveRecoveryEmail={handleSaveRecoveryEmail}
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

function SettingsView({
  vault,
  deviceId,
  theme,
  setTheme,
  handleToggleTwoFactor,
  handleLockoutPolicy,
  handleSaveRecoveryEmail,
  setDeleteTarget,
}: {
  vault: VaultPayload;
  deviceId: string;
  theme: ThemePreference;
  setTheme: (theme: ThemePreference) => void;
  handleToggleTwoFactor: () => void;
  handleLockoutPolicy: (
    maxFailedAttempts: number,
    lockoutMinutes: number,
  ) => void;
  handleSaveRecoveryEmail: (email: string) => Promise<boolean>;
  setDeleteTarget: (device: TrustedDevice) => void;
}) {
  const [notificationEmail, setNotificationEmail] = useState(
    isNotificationEmailConfigured(vault.settings.email)
      ? vault.settings.email
      : "",
  );
  const [savingEmail, setSavingEmail] = useState(false);

  useEffect(() => {
    setNotificationEmail(
      isNotificationEmailConfigured(vault.settings.email)
        ? vault.settings.email
        : "",
    );
  }, [vault.settings.email]);

  async function saveNotificationEmail(event: FormEvent) {
    event.preventDefault();
    setSavingEmail(true);
    await handleSaveRecoveryEmail(notificationEmail);
    setSavingEmail(false);
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
              void handleToggleTwoFactor();
              if (needsEmail) {
                window.requestAnimationFrame(() => {
                  document.getElementById("notification-email")?.focus();
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
