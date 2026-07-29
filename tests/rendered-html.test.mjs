import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

test("builds the 钥密 unlock experience", async () => {
  const [page, layout] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    access(new URL("../dist/server/index.js", import.meta.url)),
  ]);

  assert.match(layout, /钥密 · 安全密码管理器/);
  assert.match(page, /解锁钥密/);
  assert.match(page, /请输入主密码进入你的加密密码库/);
  assert.match(page, /首次登录默认密码/);
  assert.match(page, /12345678/);
  assert.match(page, /requiresInitialPasswordChange \?/);
  assert.match(page, /type=\{showMasterPassword \? "text" : "password"\}/);
  assert.match(page, /aria-label=\{/);
  assert.match(page, /显示主密码/);
  assert.match(page, /隐藏主密码/);
  assert.doesNotMatch(
    `${page}\n${layout}`,
    /codex-preview|SkeletonPreview|react-loading-skeleton/,
  );
});

test("includes the requested security and device-management flows", async () => {
  const [page, layout, schema, unlockRoute, vaultRoute] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/auth/unlock/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/vault/route.ts", import.meta.url), "utf8"),
  ]);

  assert.match(page, /验证新设备/);
  assert.match(page, /新设备二次验证/);
  assert.match(page, /删除已加入的设备/);
  assert.match(page, /confirmDeviceDeletion/);
  assert.match(page, /AES-GCM/);
  assert.match(layout, /钥密 · 安全密码管理器/);
  assert.match(schema, /trustedDevices/);
  assert.match(schema, /vaultEntries/);
  assert.match(schema, /loginAttempts/);
  assert.match(schema, /vaultSessions/);
  assert.match(unlockRoute, /maxFailedAttempts/);
  assert.match(unlockRoute, /lockedUntil/);
  assert.match(unlockRoute, /createVaultSession/);
  assert.match(vaultRoute, /getVaultSession/);
  assert.match(page, /密码错误锁定策略/);
});

test("supports persistent color themes and system matching", async () => {
  const [page, layout, styles] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
  ]);

  assert.match(page, /"violet"/);
  assert.match(page, /"glacier"/);
  assert.match(page, /"amber"/);
  assert.match(page, /yuemi-theme/);
  assert.match(page, /界面主题/);
  assert.match(layout, /themeBootScript/);
  assert.match(styles, /:root\[data-theme="light"\]/);
  assert.match(styles, /:root\[data-theme="violet"\]/);
  assert.match(styles, /:root\[data-theme="glacier"\]/);
  assert.match(styles, /:root\[data-theme="amber"\]/);
  assert.match(styles, /\.theme-options/);
  assert.match(styles, /\.vault-layout[\s\S]*grid-template-columns: 1fr/);
  assert.doesNotMatch(
    styles,
    /grid-template-columns: minmax\(0, 1fr\) minmax\(320px, 340px\)/,
  );
});

test("encrypts complete vault records while retaining demo access", async () => {
  const [page, vaultRoute] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/vault/route.ts", import.meta.url), "utf8"),
  ]);

  assert.match(page, /const DEMO_CODE = "246810"/);
  assert.match(page, /LEGACY_DEFAULT_RECORD_PASSWORD/);
  assert.match(page, /ENCRYPTED_RECORD_PREFIX = "yv2\."/);
  assert.match(page, /encryptVaultRecord/);
  assert.match(page, /decryptVaultRecord/);
  assert.match(page, /crypto\.getRandomValues\(new Uint8Array\(16\)\)/);
  assert.match(vaultRoute, /encryptedStorageFields/);
  assert.match(vaultRoute, /passwordCipher\.startsWith\(ENCRYPTED_RECORD_PREFIX\)/);
});

test("only exposes password recovery after email and SMTP are configured", async () => {
  const [page, vaultRoute, recoveryRoute] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/vault/route.ts", import.meta.url), "utf8"),
    readFile(
      new URL("../app/api/auth/recovery/route.ts", import.meta.url),
      "utf8",
    ),
  ]);

  assert.match(page, /recoveryAvailable/);
  assert.match(page, /recoveryStep === "code"/);
  assert.match(page, /recoveryStep === "email"/);
  assert.match(page, /action: "set-recovery-email"/);
  assert.match(page, /用于新设备验证和主密码找回/);
  assert.match(page, /document\.getElementById\("notification-email"\)\?\.focus/);
  assert.match(page, /result\.error \?\? "保存失败"/);
  assert.match(vaultRoute, /set-recovery-email/);
  assert.match(recoveryRoute, /const DEMO_CODE = "246810"/);
  assert.match(recoveryRoute, /DEFAULT_MASTER_PASSWORD/);
  assert.match(recoveryRoute, /action === "request-code"/);
  assert.match(recoveryRoute, /action === "verify-code"/);
  assert.match(recoveryRoute, /action === "send-password"/);
  assert.match(recoveryRoute, /configuredEmail\.toLowerCase\(\)/);
  assert.match(recoveryRoute, /getReadySmtpConfig/);
  assert.doesNotMatch(recoveryRoute, /demoPassword:/);
});

test("supports encrypted custom SMTP settings with optional presets", async () => {
  const [page, schema, smtpConfig, smtpClient, vaultRoute, unlockRoute] =
    await Promise.all([
      readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
      readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
      readFile(new URL("../db/smtp-config.ts", import.meta.url), "utf8"),
      readFile(new URL("../db/smtp.ts", import.meta.url), "utf8"),
      readFile(new URL("../app/api/vault/route.ts", import.meta.url), "utf8"),
      readFile(
        new URL("../app/api/auth/unlock/route.ts", import.meta.url),
        "utf8",
      ),
    ]);

  assert.match(page, /SMTP 邮件服务/);
  assert.match(page, /smtp\.qq\.com/);
  assert.match(page, /smtp\.163\.com/);
  assert.match(page, /smtp\.gmail\.com/);
  assert.match(page, /支持任意公网 SMTP 邮箱服务/);
  assert.match(page, /smtpFeatureEnabled/);
  assert.match(page, /list="smtp-provider-options"/);
  assert.match(page, /value="starttls"/);
  assert.match(page, /发送测试邮件/);
  assert.match(schema, /smtpSecretCipher/);
  assert.match(schema, /smtpVerifiedAt/);
  assert.match(schema, /smtpFeatureEnabled/);
  assert.match(schema, /smtpSecurity/);
  assert.match(smtpConfig, /SMTP_CONFIG_KEY/);
  assert.match(smtpConfig, /AES-GCM/);
  assert.match(smtpConfig, /normalizeSmtpHost/);
  assert.doesNotMatch(smtpConfig, /endsWith\("@qq\.com"\)/);
  assert.doesNotMatch(smtpConfig, /endsWith\("@163\.com"\)/);
  assert.match(smtpClient, /cloudflare:sockets/);
  assert.match(smtpClient, /AUTH LOGIN/);
  assert.match(smtpClient, /AUTH PLAIN/);
  assert.match(
    smtpClient,
    /secureTransport: input\.security === "tls" \? "on" : "starttls"/,
  );
  assert.match(smtpClient, /STARTTLS/);
  assert.match(smtpClient, /\.startTls\(\)/);
  assert.match(vaultRoute, /action === "set-smtp-config"/);
  assert.match(vaultRoute, /action === "set-smtp-feature"/);
  assert.match(vaultRoute, /action === "test-smtp"/);
  assert.match(vaultRoute, /normalizeSmtpHost\(payload\.host\)/);
  assert.match(unlockRoute, /验证码邮件发送失败/);
  assert.doesNotMatch(
    vaultRoute,
    /smtpSecretCipher:\s*settings\.smtpSecretCipher/,
  );
});

test("imports browser CSV locally and restores encrypted vault backups", async () => {
  const [page, vaultRoute, styles] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/vault/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
  ]);

  assert.match(page, /parseBrowserPasswordCsv/);
  assert.match(page, /encryptVaultRecordsBatch/);
  assert.match(page, /Chrome \/ Edge/);
  assert.match(page, /accept="\.csv,text\/csv"/);
  assert.match(page, /yuemi-encrypted-vault-backup/);
  assert.match(page, /PBKDF2/);
  assert.match(page, /AES-GCM/);
  assert.match(page, /downloadEncryptedBackup/);
  assert.match(page, /decryptEncryptedBackup/);
  assert.match(page, /\.yuemi/);
  assert.match(page, /原始 CSV 是明文文件/);
  assert.match(vaultRoute, /action === "import-entries"/);
  assert.match(vaultRoute, /passwordCipher\.startsWith/);
  assert.match(vaultRoute, /env\.DB\.batch/);
  assert.match(styles, /\.transfer-actions/);
  assert.match(styles, /\.transfer-security-note/);

  const vaultViewSource = page.slice(
    page.indexOf("function VaultView"),
    page.indexOf("function SettingsView"),
  );
  const settingsViewSource = page.slice(page.indexOf("function SettingsView"));
  assert.doesNotMatch(vaultViewSource, /vault-transfer-title/);
  assert.match(settingsViewSource, /vault-transfer-title/);
  assert.match(settingsViewSource, /handleImportEncryptedEntries/);
});

test("changes the master password by rotating encrypted records", async () => {
  const [page, vaultRoute, auth, styles] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/vault/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/auth.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
  ]);

  assert.match(page, /修改主密码/);
  assert.match(page, /preparePasswordChangeEntries/);
  assert.match(page, /action: "change-master-password"/);
  assert.match(page, /当前主密码/);
  assert.match(page, /确认新主密码/);
  assert.match(page, /此前导出的加密备份仍需使用导出时的旧主密码恢复/);
  assert.match(vaultRoute, /action === "change-master-password"/);
  assert.match(vaultRoute, /hashMasterPassword\(currentPassword\)/);
  assert.match(vaultRoute, /hashMasterPassword\(newPassword\)/);
  assert.match(vaultRoute, /DELETE FROM vault_sessions/);
  assert.match(vaultRoute, /DELETE FROM login_attempts/);
  assert.match(auth, /PBKDF2/);
  assert.match(styles, /\.password-change-form/);
  assert.match(styles, /\.password-change-grid/);
});

test("forces the first login to replace the default password", async () => {
  const [page, vaultRoute, unlockRoute, ensure, constants, styles] =
    await Promise.all([
      readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
      readFile(new URL("../app/api/vault/route.ts", import.meta.url), "utf8"),
      readFile(
        new URL("../app/api/auth/unlock/route.ts", import.meta.url),
        "utf8",
      ),
      readFile(new URL("../db/ensure.ts", import.meta.url), "utf8"),
      readFile(
        new URL("../db/security-constants.ts", import.meta.url),
        "utf8",
      ),
      readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    ]);

  assert.match(constants, /DEFAULT_MASTER_PASSWORD = "12345678"/);
  assert.match(ensure, /DEFAULT_MASTER_PASSWORD_HASH/);
  assert.match(page, /requiresPasswordChange/);
  assert.match(page, /setRequiresInitialPasswordChange/);
  assert.match(page, /requiresInitialPasswordChange \?/);
  assert.match(page, /ForcedPasswordChangeView/);
  assert.match(page, /请先修改默认主密码/);
  assert.match(page, /默认密码仅用于第一次进入/);
  assert.match(page, /disabled=\{requiresPasswordChange\}/);
  assert.match(vaultRoute, /首次进入必须先修改默认主密码/);
  assert.match(vaultRoute, /status: 428/);
  assert.match(vaultRoute, /usesLegacyDefaultEncryption/);
  assert.match(vaultRoute, /action === "abandon-first-login"/);
  assert.match(vaultRoute, /sessionRevoked: true/);
  assert.match(unlockRoute, /acceptedLegacyDefault/);
  assert.match(page, /window\.addEventListener\("pagehide"/);
  assert.match(page, /window\.addEventListener\("pageshow"/);
  assert.match(page, /keepalive: true/);
  assert.match(styles, /\.forced-password-layout/);
  assert.match(styles, /\.nav-item:disabled/);
});
