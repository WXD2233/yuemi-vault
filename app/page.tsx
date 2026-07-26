"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

type Phase = "locked" | "verify" | "vault";
type AppView = "vault" | "settings";

type VaultEntry = {
  id: string;
  projectName: string;
  account: string;
  category: string;
  securityStatus: string;
  passwordCipher: string;
  passwordIv: string;
  updatedAt: string;
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

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

async function encryptSecret(secret: string, masterPassword: string) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: new TextEncoder().encode("yue-mi-vault-v1"),
      iterations: 150_000,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(secret),
  );

  return {
    passwordCipher: bytesToBase64(new Uint8Array(cipher)),
    passwordIv: bytesToBase64(iv),
  };
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
  });

  const fetchVault = useCallback(async (token: string) => {
    try {
      const response = await fetch("/api/vault", {
        cache: "no-store",
        headers: { authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error("vault request failed");
      const payload = (await response.json()) as VaultPayload;
      setVault(payload);
    } catch {
      setToast("暂时无法读取密码库，请稍后重试");
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
    if (response.status === 401) {
      setSessionToken("");
      setVault(defaultPayload);
      setPhase("locked");
      throw new Error("本次访问已过期，请重新输入主密码");
    }
    if (!response.ok) throw new Error("保存失败");
    return response.json();
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
      await fetchVault(result.sessionToken);
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
      await fetchVault(result.sessionToken);
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
      const encrypted = await encryptSecret(entryForm.password, masterPassword);
      await postVault({
        action: "add-entry",
        projectName: entryForm.projectName,
        account: entryForm.account,
        category: entryForm.category,
        ...encrypted,
      });
      setEntryForm({
        projectName: "",
        account: "",
        category: "开发工具",
        password: "",
      });
      await fetchVault(sessionToken);
      setToast("密码已加密保存");
    } catch {
      setToast("保存失败，请稍后重试");
    }
  }

  async function handleToggleTwoFactor() {
    try {
      await postVault({
        action: "set-two-factor",
        enabled: !vault.settings.twoFactorEnabled,
      });
      await fetchVault(sessionToken);
      setToast(
        vault.settings.twoFactorEnabled
          ? "新设备二次验证已关闭"
          : "新设备二次验证已开启",
      );
    } catch {
      setToast("设置更新失败");
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
      await fetchVault(sessionToken);
      setToast("密码错误锁定策略已更新");
    } catch {
      setToast("锁定策略更新失败");
    }
  }

  async function confirmDeviceDeletion() {
    if (!deleteTarget) return;
    try {
      await postVault({ action: "delete-device", id: deleteTarget.id });
      const removedCurrentDevice = deleteTarget.id === deviceId;
      setDeleteTarget(null);
      await fetchVault(sessionToken);
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
          <button className="text-button" type="button">
            忘记主密码？
          </button>
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
            className="nav-item"
            onClick={() => {
              setView("vault");
              document
                .getElementById("password-generator")
                ?.scrollIntoView({ behavior: "smooth" });
            }}
          >
            <span>⌁</span>密码生成器
          </button>
          <button className="nav-item" onClick={() => setView("vault")}>
            <span>◇</span>安全检查
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
              {view === "settings" ? "设置 / 安全" : "个人密码空间"}
            </span>
            <h1>{view === "settings" ? "安全设置" : "密码库"}</h1>
          </div>
          <div className="topbar-actions">
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

        {view === "vault" ? (
          <VaultView
            vault={vault}
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
          />
        ) : (
          <SettingsView
            vault={vault}
            deviceId={deviceId}
            handleToggleTwoFactor={handleToggleTwoFactor}
            handleLockoutPolicy={handleLockoutPolicy}
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
  };
  setEntryForm: React.Dispatch<
    React.SetStateAction<{
      projectName: string;
      account: string;
      category: string;
      password: string;
    }>
  >;
  handleAddEntry: (event: FormEvent) => void;
};

function VaultView({
  vault,
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
}: VaultViewProps) {
  return (
    <div className="vault-layout">
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
              min="8"
              max="40"
              value={passwordLength}
              onChange={(event) => setPasswordLength(Number(event.target.value))}
            />
            <output>{passwordLength}</output>
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

        <section className="panel entries-panel">
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
                <span className="muted-account">{entry.account}</span>
                <span>
                  <em
                    className={`category-chip ${
                      categoryTone[entry.category] ?? "blue"
                    }`}
                  >
                    {entry.category}
                  </em>
                </span>
                <span className="safe-state">◇ {entry.securityStatus}</span>
                <span className="date-cell">{entry.updatedAt}</span>
                <button type="button" className="row-menu" aria-label="更多操作">
                  •••
                </button>
              </div>
            ))}
          </div>
          <div className="table-footer">
            <span>共 {vault.entries.length} 条记录</span>
            <span>密码仅以加密密文保存</span>
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
          <label>
            分类
            <select
              value={entryForm.category}
              onChange={(event) =>
                setEntryForm((current) => ({
                  ...current,
                  category: event.target.value,
                }))
              }
            >
              <option>开发工具</option>
              <option>电子邮件</option>
              <option>服务器</option>
              <option>金融</option>
              <option>社交</option>
            </select>
          </label>
          <label>
            备注
            <textarea placeholder="添加备注（可选）" rows={4} />
          </label>
          <button className="primary-button save-entry" type="submit">
            保存密码
          </button>
        </form>
      </aside>
    </div>
  );
}

function SettingsView({
  vault,
  deviceId,
  handleToggleTwoFactor,
  handleLockoutPolicy,
  setDeleteTarget,
}: {
  vault: VaultPayload;
  deviceId: string;
  handleToggleTwoFactor: () => void;
  handleLockoutPolicy: (
    maxFailedAttempts: number,
    lockoutMinutes: number,
  ) => void;
  setDeleteTarget: (device: TrustedDevice) => void;
}) {
  return (
    <div className="settings-layout">
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
            onClick={handleToggleTwoFactor}
          >
            <i />
            <span className="sr-only">切换新设备二次验证</span>
          </button>
        </div>
        <p className="settings-description">
          所有设备每次进入都会由服务端重新校验主密码；开启后，新设备还需要邮箱验证码确认身份。
        </p>
        <div className="verified-row">
          <div>
            <span>验证邮箱</span>
            <strong>{vault.settings.email}</strong>
          </div>
          <em>✓ 已验证</em>
        </div>
        <div className="security-callout">
          <ShieldMark small />
          <p>
            建议保持开启。即使主密码泄露，新设备仍无法直接读取你的密码库。
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
